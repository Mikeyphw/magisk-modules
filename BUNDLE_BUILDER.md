# Patch-aware synchronized bundle builder

This fork keeps the upstream repository intact and adds a separate bundle
pipeline.

## What it builds

The release asset is one installable Magisk module ZIP. It contains the
selected upstream module ZIPs unchanged under `payload/`.

During installation, the bundle's `customize.sh`:

1. extracts each child module into an isolated source directory;
2. recreates the normal Magisk child installation staging behavior;
3. sources the child's original `customize.sh` with child-specific `ZIPFILE`,
   `MODPATH`, and `TMPDIR`;
4. preserves permissions and symlinks produced by that installer;
5. checks every destination for collisions;
6. merges the staged payload into the final combined module;
7. dispatches supported child lifecycle hooks through the bundle module.

This is deliberately different from flattening ZIP archives on the GitHub
runner. Patches that need Android, Magisk installer functions, ABI variables,
or device properties run on the device.

## Configure selected tools

Edit `bundle.toml`.

```toml
[[tools]]
id = "python"
pattern = "python3_3.14.v*.zip"
required = true
hooks = "reject"
```

`pattern` uses shell-style matching. The newest filename under natural sorting
wins.

Hook policies:

- `reject`: draft the build if the child contains lifecycle hooks.
- `dispatch`: retain and dispatch `service.sh`, `post-fs-data.sh`,
  `boot-completed.sh`, `uninstall.sh`, and `action.sh`.
- `drop`: deliberately omit child hooks.

`customize.sh` is never dropped. It is the installation patch surface.

## Installer approval

The builder hashes installer-relevant files independently from binary payloads.
A new or changed installer surface marks the release as requiring review.

Run the **Approve current installers** workflow manually after inspecting its
audit artifact. That workflow updates `bundle-installer-lock.json`, commits it,
and triggers a normal build.

The lock is intentionally not updated by scheduled builds.

## Automatic synchronization

Two workflows are installed:

- **Sync fork from upstream** merges `bnsmb/magisk-modules/main` into this
  fork's `main` branch without force-resetting custom builder files.
- **Build synchronized bundle** also checks out upstream directly, so the build
  does not depend on the sync workflow finishing first.

## Local validation

From the fork root:

```sh
python3 -m unittest discover -s .bundle-builder/tests -v

rm -rf _bundle-upstream
git clone --depth=1 \
  https://github.com/bnsmb/magisk-modules.git \
  _bundle-upstream

python3 .bundle-builder/build_bundle.py \
  --config bundle.toml \
  --lock bundle-installer-lock.json \
  --upstream _bundle-upstream/Magisk_Modules \
  --output-dir dist \
  --upstream-commit "$(git -C _bundle-upstream rev-parse HEAD)" \
  --upstream-committed-at \
    "$(git -C _bundle-upstream show -s --format=%cI HEAD)"
```

## Limits

Shell code cannot be perfectly sandboxed inside the Magisk installer. The
builder performs static auditing, uses isolated `MODPATH` and `TMPDIR` values,
and gates changed installer logic, but an approved child installer can still
perform explicit writes outside its staging directory.

Do not approve an unfamiliar installer diff blindly.
