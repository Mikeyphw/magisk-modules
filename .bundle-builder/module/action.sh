#!/system/bin/sh
MODDIR=${0%/*}
HOOK_ROOT="$MODDIR/.bundle-hooks"

[ -d "$HOOK_ROOT" ] || exit 0

found=0
for hook in "$HOOK_ROOT"/*/action.sh; do
  [ -f "$hook" ] || continue
  found=1
  /system/bin/sh "$hook"
done

[ "$found" -eq 1 ] || printf '%s\n' "No bundled module action is available."
