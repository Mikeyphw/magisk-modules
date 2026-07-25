#!/system/bin/sh

ui_print " "
ui_print "Installing patch-aware binary bundle"
ui_print "Original child installers run in isolated staging directories"
ui_print " "

BUNDLE_MANIFEST="$MODPATH/bundle-manifest.tsv"
BUNDLE_PAYLOAD="$MODPATH/payload"
BUNDLE_WORK="$TMPDIR/magisk-bundle-work"
BUNDLE_HOOKS="$MODPATH/.bundle-hooks"

bundle_abort() {
  abort "Bundle installer: $*"
}

bundle_is_control_path() {
  case "$1" in
    META-INF|META-INF/*|module.prop|customize.sh| \
    service.sh|post-fs-data.sh|boot-completed.sh| \
    uninstall.sh|action.sh|system.prop|sepolicy.rule)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

bundle_prepare_hook_context() {
  child_id=$1
  child_stage=$2
  hook_dir="$BUNDLE_HOOKS/$child_id"

  mkdir -p "$hook_dir" || bundle_abort "cannot create hook context"

  if [ -f "$child_stage/module.prop" ]; then
    cp -af "$child_stage/module.prop" "$hook_dir/module.prop" \
      || bundle_abort "cannot preserve module.prop for $child_id"
  fi

  for hook_name in \
    service.sh post-fs-data.sh boot-completed.sh uninstall.sh action.sh
  do
    if [ -f "$child_stage/$hook_name" ]; then
      cp -af "$child_stage/$hook_name" "$hook_dir/$hook_name" \
        || bundle_abort "cannot preserve $hook_name for $child_id"
      chmod 0755 "$hook_dir/$hook_name"
    fi
  done

  for top in "$child_stage"/* "$child_stage"/.[!.]* "$child_stage"/..?*; do
    [ -e "$top" ] || [ -L "$top" ] || continue
    top_name=${top##*/}
    bundle_is_control_path "$top_name" && continue

    case "$top_name" in
      .|..) continue ;;
    esac

    if [ ! -e "$hook_dir/$top_name" ] && [ ! -L "$hook_dir/$top_name" ]; then
      ln -s "../../$top_name" "$hook_dir/$top_name" 2>/dev/null || true
    fi
  done
}

bundle_merge_special_file() {
  child_id=$1
  child_stage=$2
  special_name=$3
  source_file="$child_stage/$special_name"
  target_file="$MODPATH/$special_name"

  [ -f "$source_file" ] || return 0

  {
    printf '\n# Begin bundled module: %s\n' "$child_id"
    cat "$source_file"
    printf '\n# End bundled module: %s\n' "$child_id"
  } >>"$target_file" || bundle_abort "cannot merge $special_name"

  rm -f "$source_file"
}

bundle_remove_control_files() {
  child_stage=$1

  rm -rf "$child_stage/META-INF"
  rm -f \
    "$child_stage/module.prop" \
    "$child_stage/customize.sh" \
    "$child_stage/service.sh" \
    "$child_stage/post-fs-data.sh" \
    "$child_stage/boot-completed.sh" \
    "$child_stage/uninstall.sh" \
    "$child_stage/action.sh"
}

bundle_check_collision() {
  child_stage=$1
  relative=$2
  source_path="$child_stage/$relative"
  target_path="$MODPATH/$relative"

  if [ ! -e "$target_path" ] && [ ! -L "$target_path" ]; then
    return 0
  fi

  if [ -d "$source_path" ] && [ ! -L "$source_path" ]; then
    [ -d "$target_path" ] && [ ! -L "$target_path" ] \
      || bundle_abort "path type collision: $relative"
    return 0
  fi

  if [ -L "$source_path" ]; then
    [ -L "$target_path" ] \
      || bundle_abort "symlink collision: $relative"
    [ "$(readlink "$source_path")" = "$(readlink "$target_path")" ] \
      || bundle_abort "different symlink targets: $relative"
    return 0
  fi

  [ -f "$source_path" ] \
    || bundle_abort "unsupported staged path: $relative"
  [ -f "$target_path" ] && [ ! -L "$target_path" ] \
    || bundle_abort "file type collision: $relative"

  cmp -s "$source_path" "$target_path" \
    || bundle_abort "different files target the same path: $relative"
}

bundle_merge_tree() {
  child_stage=$1

  (
    cd "$child_stage" || exit 91
    find . -mindepth 1 -print
  ) | while IFS= read -r entry; do
    relative=${entry#./}
    [ -n "$relative" ] || continue
    bundle_check_collision "$child_stage" "$relative"
  done

  pipeline_status=$?
  [ "$pipeline_status" -eq 0 ] \
    || bundle_abort "collision scan failed"

  cp -af "$child_stage"/. "$MODPATH"/ \
    || bundle_abort "cannot merge staged child payload"
}

bundle_install_child() {
  child_id=$1
  payload_name=$2
  hooks_policy=$3

  child_zip="$BUNDLE_PAYLOAD/$payload_name"
  child_root="$BUNDLE_WORK/$child_id"
  child_source="$child_root/source"
  child_stage="$child_root/stage"
  child_tmp="$child_root/tmp"
  child_customize="$child_source/customize.sh"

  [ -f "$child_zip" ] \
    || bundle_abort "missing payload for $child_id: $payload_name"

  rm -rf "$child_root"
  mkdir -p "$child_source" "$child_stage" "$child_tmp" \
    || bundle_abort "cannot stage $child_id"

  ui_print "- Staging $child_id"

  unzip -oq "$child_zip" -d "$child_source" \
    || bundle_abort "cannot extract $child_id"

  rm -rf "$child_source/META-INF"

  skip_unzip=0
  if [ -f "$child_customize" ]; then
    if grep -Eq \
      '^[[:space:]]*(export[[:space:]]+)?SKIPUNZIP[[:space:]]*=[[:space:]]*1([[:space:]]|$)' \
      "$child_customize"
    then
      skip_unzip=1
    fi
  fi

  if [ "$skip_unzip" -eq 0 ]; then
    cp -af "$child_source"/. "$child_stage"/ \
      || bundle_abort "cannot prepare default extraction for $child_id"
  fi

  if [ -f "$child_customize" ]; then
    ui_print "  Running original customize.sh"
    (
      export ZIPFILE="$child_zip"
      export MODPATH="$child_stage"
      export TMPDIR="$child_tmp"
      export MODID="$child_id"
      cd "$child_source" || exit 92
      . "$child_customize"
    )
    child_status=$?
    [ "$child_status" -eq 0 ] \
      || bundle_abort "original installer failed for $child_id"
  fi

  case "$hooks_policy" in
    dispatch)
      bundle_prepare_hook_context "$child_id" "$child_stage"
      ;;
    drop)
      rm -f \
        "$child_stage/service.sh" \
        "$child_stage/post-fs-data.sh" \
        "$child_stage/boot-completed.sh" \
        "$child_stage/uninstall.sh" \
        "$child_stage/action.sh"
      ;;
    reject)
      for hook_name in \
        service.sh post-fs-data.sh boot-completed.sh uninstall.sh action.sh
      do
        [ ! -f "$child_stage/$hook_name" ] \
          || bundle_abort "$child_id produced rejected hook: $hook_name"
      done
      ;;
    *)
      bundle_abort "unknown hook policy for $child_id: $hooks_policy"
      ;;
  esac

  bundle_merge_special_file "$child_id" "$child_stage" system.prop
  bundle_merge_special_file "$child_id" "$child_stage" sepolicy.rule
  bundle_remove_control_files "$child_stage"
  bundle_merge_tree "$child_stage"

  rm -rf "$child_root"
}

[ -f "$BUNDLE_MANIFEST" ] \
  || bundle_abort "bundle-manifest.tsv is missing"
[ -d "$BUNDLE_PAYLOAD" ] \
  || bundle_abort "payload directory is missing"

rm -rf "$BUNDLE_WORK"
mkdir -p "$BUNDLE_WORK" "$BUNDLE_HOOKS" \
  || bundle_abort "cannot create bundle work directories"

while IFS='|' read -r child_id payload_name hooks_policy source_name archive_sha
do
  [ -n "$child_id" ] || continue
  case "$child_id" in
    \#*) continue ;;
  esac

  bundle_install_child "$child_id" "$payload_name" "$hooks_policy"
done <"$BUNDLE_MANIFEST"

rm -rf "$BUNDLE_PAYLOAD" "$BUNDLE_WORK"
rm -f "$BUNDLE_MANIFEST"

# Do not reset the merged tree recursively. Child installers may have applied
# executable, setuid, or data-file modes that are part of their patch logic.
# Only the bundle-owned dispatcher scripts are normalized here.

for top_hook in \
  service.sh post-fs-data.sh boot-completed.sh uninstall.sh action.sh
do
  [ -f "$MODPATH/$top_hook" ] && chmod 0755 "$MODPATH/$top_hook"
done

if [ -d "$BUNDLE_HOOKS" ]; then
  find "$BUNDLE_HOOKS" -type f -name '*.sh' -exec chmod 0755 {} \;
fi

ui_print " "
ui_print "Bundle installation complete"
ui_print " "
