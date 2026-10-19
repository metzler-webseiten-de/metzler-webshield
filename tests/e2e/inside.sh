#!/usr/bin/env bash
# Runs inside the wordpress:cli container, started by run.sh
set -euo pipefail

E2E=/src/tests/e2e
cd /var/www/html

# The image runs WP-CLI with PHP's default 128 MB, too little to unpack WordPress and the big plugins
wp() { php -d memory_limit=1G /usr/local/bin/wp "$@"; }

# Popular plugins, including the kinds that write .htaccess, drop-ins or generated files
ACTIVATE=(
    woocommerce elementor wpforms-lite contact-form-7 wordpress-seo updraftplus
    w3-total-cache litespeed-cache jetpack all-in-one-wp-migration duplicator
    really-simple-ssl formidable siteorigin-panels so-widgets-bundle cookie-law-info
    redirection wp-mail-smtp classic-editor advanced-custom-fields
)
# Installed but not activated: other firewalls would interfere with Webshield
INSTALL_ONLY=( wordfence better-wp-security all-in-one-wp-security-and-firewall wp-file-manager sucuri-scanner )

echo "::group::Install WordPress"
wp core download --quiet
wp config create --dbname=wordpress --dbuser=wordpress --dbpass=wordpress --dbhost=db --skip-check --quiet
chmod 644 wp-config.php
wp core install --url=http://localhost --title="Webshield E2E" --admin_user=e2e-tester \
    --admin_password="$(head -c 18 /dev/urandom | base64)" --admin_email=e2e@example.com --skip-email --quiet
echo "::endgroup::"

echo "::group::Install plugins"
for slug in "${ACTIVATE[@]}"; do
    wp plugin install "$slug" --activate --quiet || echo "::warning::Could not install $slug"
done
for slug in "${INSTALL_ONLY[@]}"; do
    wp plugin install "$slug" --quiet || echo "::warning::Could not install $slug"
done
wp plugin list --fields=name,status,version
echo "::endgroup::"

echo "::group::Install Metzler Webshield from source"
mkdir -p wp-content/plugins/metzler-webshield
cp -r /src/admin /src/assets /src/includes /src/metzler-webshield.php /src/uninstall.php /src/readme.txt \
    wp-content/plugins/metzler-webshield/
wp plugin activate metzler-webshield
echo "::endgroup::"

scan() {
    wp eval 'Metzler_Webshield_Queue::cron_start_scan();'
}

echo "::group::Scan the clean site"
# The first scan creates the FIM baseline, the second one compares against it
scan
scan
echo "::endgroup::"
status=0
wp eval-file "$E2E/check.php" clean || status=1

echo "::group::Plant samples and scan again"
wp eval 'global $wpdb; $wpdb->query("TRUNCATE TABLE {$wpdb->prefix}metzler_webshield_logs");'
while IFS="|" read -r sample target expected; do
    sample="${sample// /}"; target="${target// /}"
    [[ -z "$sample" || "$sample" == \#* ]] && continue
    [[ "$sample" == @* && "$sample" != "@append" ]] || mkdir -p "$(dirname "$target")"
    if [[ "$sample" == "@append" ]]; then
        echo "// e2e: modified copy" >> "$target"
    elif [[ "$sample" == "@plugin-install" ]]; then
        wp plugin install "$target" --quiet < /dev/null
    elif [[ "$sample" == "@user-cap" ]]; then
        wp user create "$target" "$target@example.com" --role=editor --quiet < /dev/null
        wp user add-cap "$target" install_plugins < /dev/null
    else
        cp "$E2E/samples/$sample" "$target"
    fi
done < "$E2E/expected.txt"
scan
echo "::endgroup::"
wp eval-file "$E2E/check.php" detect "$E2E/expected.txt" || status=1

exit $status
