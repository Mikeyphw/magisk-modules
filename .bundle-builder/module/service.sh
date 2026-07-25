#!/system/bin/sh
MODDIR=${0%/*}
HOOK_ROOT="$MODDIR/.bundle-hooks"

[ -d "$HOOK_ROOT" ] || exit 0

for hook in "$HOOK_ROOT"/*/service.sh; do
  [ -f "$hook" ] || continue
  /system/bin/sh "$hook" &
done
