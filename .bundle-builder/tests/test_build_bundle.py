from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
import zipfile
import sys
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "build_bundle.py"
SPEC = importlib.util.spec_from_file_location("build_bundle", MODULE_PATH)
assert SPEC and SPEC.loader
build_bundle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = build_bundle
SPEC.loader.exec_module(build_bundle)


def write_zip(path: Path, entries: dict[str, bytes]) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)


class BuilderTests(unittest.TestCase):
    def test_natural_sort_selects_newest_filename(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            write_zip(root / "bash_5.2.9.zip", {"system/bin/bash": b"old"})
            write_zip(root / "bash_5.2.37.zip", {"system/bin/bash": b"new"})

            config = build_bundle.ToolConfig(
                tool_id="bash",
                pattern="bash_*.zip",
                required=True,
                hooks="reject",
            )
            selected = build_bundle.select_tools(
                root,
                [config],
                10 * 1024 * 1024,
            )
            self.assertEqual(selected[0].source.name, "bash_5.2.37.zip")

    def test_path_traversal_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            archive = Path(temp) / "bad.zip"
            write_zip(archive, {"../escape": b"x"})
            with self.assertRaises(build_bundle.BuildError):
                build_bundle.inspect_archive(archive, 1024 * 1024)

    def test_changed_installer_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "tool_1.zip"
            write_zip(
                archive,
                {
                    "customize.sh": b'ui_print "patch"\n',
                    "system/bin/tool": b"binary",
                },
            )
            config = build_bundle.ToolConfig(
                tool_id="tool",
                pattern="tool_*.zip",
                required=True,
                hooks="reject",
            )
            selected = build_bundle.select_tools(
                root,
                [config],
                10 * 1024 * 1024,
            )
            build_bundle.apply_lock(
                selected,
                {"schema": 1, "tools": {}},
            )
            self.assertTrue(selected[0].review_required)

            lock_path = root / "lock.json"
            build_bundle.write_lock(lock_path, selected)
            build_bundle.apply_lock(
                selected,
                json.loads(lock_path.read_text()),
            )
            self.assertFalse(selected[0].review_required)

    def test_hook_reject_policy_requires_review(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = root / "tool_1.zip"
            write_zip(
                archive,
                {
                    "service.sh": b"#!/system/bin/sh\n",
                    "system/bin/tool": b"binary",
                },
            )
            config = build_bundle.ToolConfig(
                tool_id="tool",
                pattern="tool_*.zip",
                required=True,
                hooks="reject",
            )
            selected = build_bundle.select_tools(
                root,
                [config],
                10 * 1024 * 1024,
            )
            build_bundle.write_lock(root / "lock.json", selected)
            build_bundle.apply_lock(
                selected,
                json.loads((root / "lock.json").read_text()),
            )
            self.assertTrue(selected[0].review_required)
            self.assertIn("lifecycle hooks", selected[0].review_reason)

    def test_output_embeds_unchanged_child_zip(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            upstream = root / "upstream"
            upstream.mkdir()
            child = upstream / "tool_1.zip"
            write_zip(child, {"system/bin/tool": b"binary"})
            template = upstream / "magisk_module_template_v1.zip"
            write_zip(
                template,
                {
                    "META-INF/com/google/android/update-binary": b"#!/sbin/sh\n",
                    "META-INF/com/google/android/updater-script": b"#MAGISK\n",
                },
            )

            config = build_bundle.ToolConfig(
                tool_id="tool",
                pattern="tool_*.zip",
                required=True,
                hooks="reject",
            )
            selected = build_bundle.select_tools(
                upstream,
                [config],
                10 * 1024 * 1024,
            )
            bundle = {
                "id": "test_bundle",
                "name": "Test Bundle",
                "author": "Tester",
                "description": "Test",
            }
            module_files = {
                "customize.sh": b"#!/system/bin/sh\n",
                "service.sh": b"#!/system/bin/sh\n",
                "post-fs-data.sh": b"#!/system/bin/sh\n",
                "boot-completed.sh": b"#!/system/bin/sh\n",
                "uninstall.sh": b"#!/system/bin/sh\n",
                "action.sh": b"#!/system/bin/sh\n",
            }
            output = root / "bundle.zip"
            provenance = {"schema": 1}

            build_bundle.build_zip(
                output,
                bundle,
                selected,
                template,
                module_files,
                "v1",
                1,
                provenance,
            )

            with zipfile.ZipFile(output) as archive:
                payload_name = "payload/tool--tool_1.zip"
                self.assertEqual(
                    archive.read(payload_name),
                    child.read_bytes(),
                )
                self.assertIn("bundle-manifest.tsv", archive.namelist())
                self.assertIn("customize.sh", archive.namelist())


if __name__ == "__main__":
    unittest.main()
