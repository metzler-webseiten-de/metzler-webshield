#!/usr/bin/env bash
# Builds the release ZIPs of Metzler Webshield into dist/:
#   metzler-webshield-selfhosted.zip  with the self-hosted updater (Update URI) for metzler-webshield.de
#   metzler-webshield-wporg.zip       for WordPress.org: updater file, Update URI header and @selfhosted blocks removed
#
# Switching to WordPress.org: once the plugin is live there, publish the wporg ZIP as the last self-hosted
# release (PLUGIN_DOWNLOAD_URL). Sites update to it, lose the Update URI and get updates from WordPress.org.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SLUG="metzler-webshield"
DIST="$ROOT/dist"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

rm -rf "$DIST"
mkdir -p "$DIST"

copy_sources() {
    local target="$1/$SLUG"
    mkdir -p "$target"
    # Git-visible files only (tracked + new, not ignored), so local junk never ends up in a release
    git -C "$ROOT" ls-files -z --cached --others --exclude-standard | grep -zv -e '^bin/' -e '^dist/' -e '^\.gitignore$' -e '^\.idea/' \
        | (cd "$ROOT" && xargs -0 cp --parents -t "$target")
}

# 1. Self-hosted build: sources as they are
copy_sources "$WORK/selfhosted"
(cd "$WORK/selfhosted" && zip -qr "$DIST/$SLUG-selfhosted.zip" "$SLUG")

# 2. WordPress.org build
copy_sources "$WORK/wporg"
WPORG="$WORK/wporg/$SLUG"
rm -f "$WPORG/includes/class-metzler-webshield-updater.php"
sed -i '/^ \* Update URI:/d' "$WPORG/$SLUG.php"
find "$WPORG" -name '*.php' -print0 | xargs -0 sed -i '/@selfhosted-start/,/@selfhosted-end/d'

if grep -rqE --include='*.php' 'Update URI|Metzler_Webshield_Updater|@selfhosted' "$WPORG"; then
    echo "WordPress.org build still contains self-hosted update code:" >&2
    grep -rnE --include='*.php' 'Update URI|Metzler_Webshield_Updater|@selfhosted' "$WPORG" >&2
    exit 1
fi
find "$WPORG" -name '*.php' -print0 | xargs -0 -n1 php -l >/dev/null

(cd "$WORK/wporg" && zip -qr "$DIST/$SLUG-wporg.zip" "$SLUG")

ls -l "$DIST"
