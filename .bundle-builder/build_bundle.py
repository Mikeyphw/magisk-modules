#!/usr/bin/env python3
"""Build one patch-aware Magisk module from selected upstream module ZIPs."""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Iterable

SCHEMA_VERSION = 1
HOOK_NAMES = (
    "service.sh",
    "post-fs-data.sh",
    "boot-completed.sh",
    "uninstall.sh",
    "action.sh",
)
ROOT_CONTROL_NAMES = {
    "customize.sh",
    *HOOK_NAMES,
    "system.prop",
    "sepolicy.rule",
}
PAYLOAD_PREFIXES = (
    "system/",
    "vendor/",
    "product/",
    "system_ext/",
    "odm/",
    "zygisk/",
)
TEXT_SCRIPT_SUFFIXES = (".sh", ".rc")
FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)


class BuildError(RuntimeError):
    pass


@dataclasses.dataclass(frozen=True)
class ToolConfig:
    tool_id: str
    pattern: str
    required: bool
    hooks: str


@dataclasses.dataclass
class SelectedTool:
    config: ToolConfig
    source: Path
    archive_sha256: str
    archive_size: int
    uncompressed_size: int
    installer_files: dict[str, str]
    installer_surface_sha256: str
    hooks_present: list[str]
    findings: list[dict[str, str]]
    review_required: bool = False
    review_reason: str = ""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--lock", required=True, type=Path)
    parser.add_argument("--write-lock", type=Path)
    parser.add_argument("--upstream", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--upstream-commit", required=True)
    parser.add_argument("--upstream-committed-at", required=True)
    return parser.parse_args()


def load_toml(path: Path) -> dict[str, Any]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise BuildError(f"cannot read config {path}: {exc}") from exc


def parse_config(raw: dict[str, Any]) -> tuple[dict[str, Any], list[ToolConfig]]:
    bundle = raw.get("bundle")
    if not isinstance(bundle, dict):
        raise BuildError("bundle.toml must contain [bundle]")

    required_bundle = (
        "id",
        "name",
        "author",
        "description",
        "output_name",
        "template_pattern",
        "upstream_repository",
        "base_version",
    )
    for key in required_bundle:
        if not isinstance(bundle.get(key), str) or not bundle[key].strip():
            raise BuildError(f"[bundle].{key} must be a non-empty string")

    tools_raw = raw.get("tools")
    if not isinstance(tools_raw, list) or not tools_raw:
        raise BuildError("bundle.toml must contain at least one [[tools]] entry")

    tools: list[ToolConfig] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(tools_raw, start=1):
        if not isinstance(item, dict):
            raise BuildError(f"[[tools]] entry {index} is not a table")
        tool_id = str(item.get("id", "")).strip()
        pattern = str(item.get("pattern", "")).strip()
        required = bool(item.get("required", True))
        hooks = str(item.get("hooks", "reject")).strip()

        if not re.fullmatch(r"[A-Za-z0-9_.-]+", tool_id):
            raise BuildError(f"invalid tool id: {tool_id!r}")
        if tool_id in seen_ids:
            raise BuildError(f"duplicate tool id: {tool_id}")
        if not pattern or "/" in pattern or "\\" in pattern:
            raise BuildError(
                f"tool {tool_id}: pattern must match a direct filename"
            )
        if hooks not in {"reject", "dispatch", "drop"}:
            raise BuildError(
                f"tool {tool_id}: hooks must be reject, dispatch, or drop"
            )
        seen_ids.add(tool_id)
        tools.append(ToolConfig(tool_id, pattern, required, hooks))

    return bundle, tools


def natural_key(value: str) -> list[tuple[int, Any]]:
    parts = re.split(r"(\d+)", value.casefold())
    key: list[tuple[int, Any]] = []
    for part in parts:
        if part.isdigit():
            key.append((0, int(part)))
        else:
            key.append((1, part))
    return key


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_member_name(raw_name: str) -> str:
    if "\x00" in raw_name:
        raise BuildError("ZIP member contains NUL")
    normalized = raw_name.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute():
        raise BuildError(f"ZIP member uses absolute path: {raw_name}")
    if any(part in {"", ".", ".."} for part in path.parts):
        raise BuildError(f"ZIP member has unsafe path: {raw_name}")
    return str(path)


def is_installer_surface(name: str) -> bool:
    lowered = name.casefold()
    base = PurePosixPath(lowered).name

    if lowered.startswith("meta-inf/"):
        return False
    if lowered in ROOT_CONTROL_NAMES:
        return True
    if base in ROOT_CONTROL_NAMES:
        return True
    if lowered.endswith(TEXT_SCRIPT_SUFFIXES):
        return not lowered.startswith(PAYLOAD_PREFIXES)
    if lowered.startswith(("common/", "installer/", "install/", "tools/")):
        return True
    return False


def decode_script(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def scan_script(name: str, data: bytes) -> list[dict[str, str]]:
    text = decode_script(data)
    findings: list[dict[str, str]] = []

    checks = (
        (
            "absolute-write",
            re.compile(
                r"(?:^|[\s\"'])(?:>|>>|rm\s+-[^\n]*|cp\s+|mv\s+|mkdir\s+)"
                r"/(?:data|system|vendor|product|odm|apex)(?:/|\s)",
                re.MULTILINE,
            ),
            "installer may write to an absolute device path",
        ),
        (
            "mount-operation",
            re.compile(r"(^|[;&|]\s*)mount(?:\s|$)", re.MULTILINE),
            "installer invokes mount",
        ),
        (
            "block-write",
            re.compile(r"(^|[;&|]\s*)dd\s+[^#\n]*\bof=/dev/", re.MULTILINE),
            "installer may write directly to a block device",
        ),
        (
            "property-change",
            re.compile(r"\b(?:setprop|resetprop)\b"),
            "installer changes Android properties",
        ),
        (
            "network-access",
            re.compile(r"(^|[;&|]\s*)(?:curl|wget)\s", re.MULTILINE),
            "installer performs network access",
        ),
        (
            "nested-module-install",
            re.compile(r"\bmagisk\s+--install-module\b"),
            "installer invokes a nested Magisk module installation",
        ),
    )

    for code, pattern, message in checks:
        if pattern.search(text):
            findings.append(
                {"file": name, "severity": "warning", "code": code, "message": message}
            )
    return findings


def inspect_archive(
    path: Path,
    max_uncompressed_bytes: int,
) -> tuple[int, dict[str, str], str, list[str], list[dict[str, str]]]:
    installer_files: dict[str, str] = {}
    installer_parts: list[bytes] = []
    hooks_present: list[str] = []
    findings: list[dict[str, str]] = []
    total = 0
    seen: set[str] = set()

    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist():
                safe_name = safe_member_name(info.filename)
                if safe_name in seen:
                    raise BuildError(
                        f"{path.name}: duplicate ZIP member {safe_name}"
                    )
                seen.add(safe_name)
                total += info.file_size
                if total > max_uncompressed_bytes:
                    raise BuildError(
                        f"{path.name}: uncompressed content exceeds configured limit"
                    )
                if info.is_dir():
                    continue

                lowered = safe_name.casefold()
                if lowered in HOOK_NAMES:
                    hooks_present.append(lowered)

                if is_installer_surface(lowered):
                    data = archive.read(info)
                    digest = sha256_bytes(data)
                    installer_files[safe_name] = digest
                    installer_parts.extend(
                        (
                            safe_name.encode("utf-8"),
                            b"\0",
                            digest.encode("ascii"),
                            b"\0",
                        )
                    )
                    if lowered.endswith(TEXT_SCRIPT_SUFFIXES) or lowered.endswith(
                        "customize.sh"
                    ):
                        findings.extend(scan_script(safe_name, data))
    except zipfile.BadZipFile as exc:
        raise BuildError(f"invalid ZIP archive {path}: {exc}") from exc

    surface_hash = sha256_bytes(b"".join(installer_parts))
    return (
        total,
        dict(sorted(installer_files.items())),
        surface_hash,
        sorted(set(hooks_present)),
        findings,
    )


def select_tools(
    upstream: Path,
    configs: Iterable[ToolConfig],
    max_uncompressed_bytes: int,
) -> list[SelectedTool]:
    if not upstream.is_dir():
        raise BuildError(f"upstream module directory does not exist: {upstream}")

    available = [path for path in upstream.iterdir() if path.is_file()]
    selected: list[SelectedTool] = []
    selected_sources: set[Path] = set()

    for config in configs:
        candidates = [
            path
            for path in available
            if fnmatch.fnmatchcase(path.name, config.pattern)
        ]
        candidates.sort(key=lambda path: natural_key(path.name))

        if not candidates:
            if config.required:
                raise BuildError(
                    f"tool {config.tool_id}: no file matches {config.pattern!r}"
                )
            continue

        source = candidates[-1]
        if source in selected_sources:
            raise BuildError(
                f"upstream archive selected more than once: {source.name}"
            )
        selected_sources.add(source)

        (
            uncompressed_size,
            installer_files,
            installer_surface_sha256,
            hooks_present,
            findings,
        ) = inspect_archive(source, max_uncompressed_bytes)

        if hooks_present and config.hooks == "reject":
            findings.append(
                {
                    "file": ", ".join(hooks_present),
                    "severity": "review",
                    "code": "rejected-hooks",
                    "message": (
                        f"tool policy rejects lifecycle hooks for {config.tool_id}"
                    ),
                }
            )

        selected.append(
            SelectedTool(
                config=config,
                source=source,
                archive_sha256=sha256_file(source),
                archive_size=source.stat().st_size,
                uncompressed_size=uncompressed_size,
                installer_files=installer_files,
                installer_surface_sha256=installer_surface_sha256,
                hooks_present=hooks_present,
                findings=findings,
            )
        )

    return selected


def load_lock(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {"schema": SCHEMA_VERSION, "tools": {}}
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BuildError(f"cannot read installer lock {path}: {exc}") from exc
    if raw.get("schema") != SCHEMA_VERSION:
        raise BuildError(f"unsupported installer lock schema in {path}")
    if not isinstance(raw.get("tools"), dict):
        raise BuildError("installer lock tools must be an object")
    return raw


def apply_lock(selected: list[SelectedTool], lock: dict[str, Any]) -> None:
    locked_tools = lock.get("tools", {})
    for tool in selected:
        current = {
            "installer_surface_sha256": tool.installer_surface_sha256,
            "installer_files": tool.installer_files,
            "hooks_policy": tool.config.hooks,
        }
        locked = locked_tools.get(tool.config.tool_id)
        reasons: list[str] = []
        if locked != current:
            reasons.append("installer surface is new or changed")
        if tool.hooks_present and tool.config.hooks == "reject":
            reasons.append("lifecycle hooks are present but policy is reject")
        tool.review_required = bool(reasons)
        tool.review_reason = "; ".join(reasons)


def write_lock(path: Path, selected: list[SelectedTool]) -> None:
    data = {
        "schema": SCHEMA_VERSION,
        "description": "Approved installer surfaces generated by build_bundle.py.",
        "tools": {
            tool.config.tool_id: {
                "installer_surface_sha256": tool.installer_surface_sha256,
                "installer_files": tool.installer_files,
                "hooks_policy": tool.config.hooks,
            }
            for tool in selected
        },
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_committed_at(value: str) -> dt.datetime:
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise BuildError(f"invalid --upstream-committed-at: {value}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def template_entries(template_zip: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    with zipfile.ZipFile(template_zip) as archive:
        for required in (
            "META-INF/com/google/android/update-binary",
            "META-INF/com/google/android/updater-script",
        ):
            try:
                result[required] = archive.read(required)
            except KeyError as exc:
                raise BuildError(
                    f"template {template_zip.name} is missing {required}"
                ) from exc
    return result


def select_template(upstream: Path, pattern: str) -> Path:
    matches = [
        path
        for path in upstream.iterdir()
        if path.is_file() and fnmatch.fnmatchcase(path.name, pattern)
    ]
    matches.sort(key=lambda path: natural_key(path.name))
    if not matches:
        raise BuildError(f"no Magisk template matches {pattern!r}")
    return matches[-1]


def load_module_templates(script_dir: Path) -> dict[str, bytes]:
    module_dir = script_dir / "module"
    names = (
        "customize.sh",
        "service.sh",
        "post-fs-data.sh",
        "boot-completed.sh",
        "uninstall.sh",
        "action.sh",
    )
    result: dict[str, bytes] = {}
    for name in names:
        path = module_dir / name
        if not path.is_file():
            raise BuildError(f"module template file is missing: {path}")
        result[name] = path.read_bytes()
    return result


def calculate_fingerprint(
    bundle: dict[str, Any],
    selected: list[SelectedTool],
    template: Path,
    module_files: dict[str, bytes],
) -> str:
    digest = hashlib.sha256()
    relevant_bundle = {
        key: bundle[key]
        for key in sorted(bundle)
        if key not in {"publish_unreviewed"}
    }
    digest.update(
        json.dumps(relevant_bundle, sort_keys=True, separators=(",", ":")).encode()
    )
    digest.update(template.name.encode())
    digest.update(sha256_file(template).encode())
    for tool in selected:
        digest.update(tool.config.tool_id.encode())
        digest.update(tool.source.name.encode())
        digest.update(tool.archive_sha256.encode())
        digest.update(tool.config.hooks.encode())
    for name, data in sorted(module_files.items()):
        digest.update(name.encode())
        digest.update(sha256_bytes(data).encode())
    return digest.hexdigest()


def zip_info(name: str, executable: bool = False) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
    mode = 0o755 if executable else 0o644
    info.external_attr = (stat.S_IFREG | mode) << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    return info


def write_entry(
    archive: zipfile.ZipFile,
    name: str,
    data: bytes,
    executable: bool = False,
) -> None:
    archive.writestr(zip_info(name, executable=executable), data)


def make_module_prop(
    bundle: dict[str, Any],
    version: str,
    version_code: int,
) -> bytes:
    lines = [
        f"id={bundle['id']}",
        f"name={bundle['name']}",
        f"version={version}",
        f"versionCode={version_code}",
        f"author={bundle['author']}",
        f"description={bundle['description']}",
    ]
    update_json = bundle.get("update_json")
    if isinstance(update_json, str) and update_json.strip():
        lines.append(f"updateJson={update_json.strip()}")
    return ("\n".join(lines) + "\n").encode("utf-8")


def manifest_tsv(selected: list[SelectedTool]) -> bytes:
    lines = [
        "# child_id|payload_name|hooks_policy|source_name|archive_sha256"
    ]
    for tool in selected:
        payload_name = f"{tool.config.tool_id}--{tool.source.name}"
        lines.append(
            "|".join(
                (
                    tool.config.tool_id,
                    payload_name,
                    tool.config.hooks,
                    tool.source.name,
                    tool.archive_sha256,
                )
            )
        )
    return ("\n".join(lines) + "\n").encode("utf-8")


def provenance_data(
    bundle: dict[str, Any],
    selected: list[SelectedTool],
    upstream_commit: str,
    upstream_committed_at: str,
    fingerprint: str,
    template: Path,
) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "bundle": {
            "id": bundle["id"],
            "name": bundle["name"],
            "fingerprint": fingerprint,
        },
        "upstream": {
            "repository": bundle["upstream_repository"],
            "commit": upstream_commit,
            "committed_at": upstream_committed_at,
            "template_archive": template.name,
            "template_sha256": sha256_file(template),
        },
        "tools": [
            {
                "id": tool.config.tool_id,
                "source_archive": tool.source.name,
                "archive_sha256": tool.archive_sha256,
                "archive_size": tool.archive_size,
                "uncompressed_size": tool.uncompressed_size,
                "hooks_policy": tool.config.hooks,
                "hooks_present": tool.hooks_present,
                "installer_surface_sha256": tool.installer_surface_sha256,
                "installer_files": tool.installer_files,
            }
            for tool in selected
        ],
    }


def audit_data(selected: list[SelectedTool]) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "review_required": any(tool.review_required for tool in selected),
        "tools": [
            {
                "id": tool.config.tool_id,
                "source_archive": tool.source.name,
                "review_required": tool.review_required,
                "review_reason": tool.review_reason,
                "hooks_policy": tool.config.hooks,
                "hooks_present": tool.hooks_present,
                "findings": tool.findings,
            }
            for tool in selected
        ],
    }


def build_release_notes(
    bundle: dict[str, Any],
    selected: list[SelectedTool],
    fingerprint: str,
    upstream_commit: str,
    review_required: bool,
) -> str:
    status = (
        "Draft: installer review is required."
        if review_required
        else "Installer surfaces match the approved lock."
    )
    lines = [
        f"# {bundle['name']}",
        "",
        status,
        "",
        f"- Bundle fingerprint: `{fingerprint}`",
        f"- Upstream commit: `{upstream_commit}`",
        "",
        "## Selected modules",
        "",
    ]
    for tool in selected:
        review = " review required" if tool.review_required else ""
        lines.append(
            f"- `{tool.config.tool_id}`: `{tool.source.name}`"
            f" (`{tool.archive_sha256[:12]}`){review}"
        )
    lines.extend(
        [
            "",
            "The selected upstream archives are embedded unchanged. Their original "
            "`customize.sh` logic runs on-device in isolated staging directories "
            "before collision-checked merging.",
            "",
        ]
    )
    return "\n".join(lines)


def build_zip(
    output_path: Path,
    bundle: dict[str, Any],
    selected: list[SelectedTool],
    template: Path,
    module_files: dict[str, bytes],
    version: str,
    version_code: int,
    provenance: dict[str, Any],
) -> None:
    template_meta = template_entries(template)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with tempfile.NamedTemporaryFile(
        prefix=output_path.name, suffix=".tmp", dir=output_path.parent, delete=False
    ) as handle:
        temp_path = Path(handle.name)

    try:
        with zipfile.ZipFile(
            temp_path,
            "w",
            compression=zipfile.ZIP_DEFLATED,
            compresslevel=9,
            allowZip64=True,
        ) as archive:
            for name, data in sorted(template_meta.items()):
                write_entry(archive, name, data, executable=name.endswith("update-binary"))

            write_entry(
                archive,
                "module.prop",
                make_module_prop(bundle, version, version_code),
            )
            for name, data in sorted(module_files.items()):
                write_entry(archive, name, data, executable=True)

            write_entry(archive, "bundle-manifest.tsv", manifest_tsv(selected))
            write_entry(
                archive,
                "provenance.json",
                (
                    json.dumps(provenance, indent=2, sort_keys=True) + "\n"
                ).encode("utf-8"),
            )

            for tool in selected:
                payload_name = f"{tool.config.tool_id}--{tool.source.name}"
                info = zip_info(f"payload/{payload_name}")
                info.compress_type = zipfile.ZIP_STORED
                with tool.source.open("rb") as source, archive.open(info, "w") as target:
                    shutil.copyfileobj(source, target, length=1024 * 1024)

        temp_path.replace(output_path)
    finally:
        temp_path.unlink(missing_ok=True)


def main() -> int:
    args = parse_args()
    raw_config = load_toml(args.config)
    bundle, tool_configs = parse_config(raw_config)

    max_mib = int(bundle.get("max_archive_uncompressed_mib", 2048))
    if max_mib <= 0:
        raise BuildError("max_archive_uncompressed_mib must be positive")
    max_uncompressed_bytes = max_mib * 1024 * 1024

    selected = select_tools(
        args.upstream,
        tool_configs,
        max_uncompressed_bytes,
    )
    if not selected:
        raise BuildError("selection produced no tools")

    lock = load_lock(args.lock)
    apply_lock(selected, lock)

    if args.write_lock:
        write_lock(args.write_lock, selected)
        lock = load_lock(args.write_lock)
        apply_lock(selected, lock)

    template = select_template(args.upstream, bundle["template_pattern"])
    script_dir = Path(__file__).resolve().parent
    module_files = load_module_templates(script_dir)

    committed_at = parse_committed_at(args.upstream_committed_at)
    fingerprint = calculate_fingerprint(
        bundle,
        selected,
        template,
        module_files,
    )[:16]

    base_version = bundle["base_version"]
    version = f"v{base_version}-b{fingerprint}"
    version_code = int(committed_at.strftime("%y%m%d%H"))

    review_required = any(tool.review_required for tool in selected)
    if bundle.get("publish_unreviewed", False):
        review_required = False

    provenance = provenance_data(
        bundle,
        selected,
        args.upstream_commit,
        committed_at.isoformat().replace("+00:00", "Z"),
        fingerprint,
        template,
    )
    audit = audit_data(selected)
    audit["review_required"] = review_required

    output_dir = args.output_dir
    output_dir.mkdir(parents=True, exist_ok=True)
    asset_name = f"{bundle['output_name']}-{fingerprint}.zip"
    output_path = output_dir / asset_name

    build_zip(
        output_path,
        bundle,
        selected,
        template,
        module_files,
        version,
        version_code,
        provenance,
    )

    (output_dir / "provenance.json").write_text(
        json.dumps(provenance, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output_dir / "audit-report.json").write_text(
        json.dumps(audit, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    tag = f"bundle-{fingerprint}"
    release_title = f"{bundle['name']} {version}"
    notes = build_release_notes(
        bundle,
        selected,
        fingerprint,
        args.upstream_commit,
        review_required,
    )
    (output_dir / "release-notes.md").write_text(notes, encoding="utf-8")

    archive_sha = sha256_file(output_path)
    (output_dir / "SHA256SUMS").write_text(
        f"{archive_sha}  {asset_name}\n",
        encoding="utf-8",
    )

    meta = {
        "schema": SCHEMA_VERSION,
        "tag": tag,
        "asset_name": asset_name,
        "asset_sha256": archive_sha,
        "fingerprint": fingerprint,
        "version": version,
        "version_code": version_code,
        "review_required": review_required,
        "release_title": release_title,
        "upstream_commit": args.upstream_commit,
    }
    (output_dir / "build-meta.json").write_text(
        json.dumps(meta, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(meta, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BuildError as exc:
        print(f"build error: {exc}", file=sys.stderr)
        raise SystemExit(2)
