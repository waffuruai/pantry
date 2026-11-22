use super::*;

#[test]
fn generic_rules_skip_translations_bundles_styles_and_docs() {
    for path in [
        "app/src/lang/translations/hu-HU.yaml",
        "api/locales/en.json",
        "src/i18n/de.ts",
        "app/lib/l10n/app_pt.arb",
        "po/fr.po",
        "Base.lproj/Localizable.strings",
        "src/main/resources/messages_de.properties",
        "public/admin/js/app.6fb2ab18.js",
        "public/admin/js/chunk-2d0b219a-legacy.92a44bfd.js",
        "vendor/jquery.min.js",
        "dist/app.js.map",
        "assets/css/directus.css",
        "README.md",
        "documentation/modules/exploit/linux/http/php_imap_open_rce.md",
        "docs/setup.txt",
    ] {
        for rule in ["generic-password", "generic-api-key", "generic-credential-uri"] {
            assert!(skips(rule, path), "{rule} reads {path}");
        }
    }
}

#[test]
fn only_the_generic_password_rule_skips_tests() {
    for path in [
        "spec/lib/rex/proto/sms/client_spec.rb",
        "api/src/websocket/authenticate.test.ts",
        "backend/tests/unit/test_speaker_sample.py",
        "pkg/auth/login_test.go",
        "web/__mocks__/api.js",
        "e2e/login-spec.js",
    ] {
        assert!(skips("generic-password", path), "generic-password reads {path}");
        assert!(!skips("generic-api-key", path), "generic-api-key skips {path}");
    }
}

#[test]
fn provider_rules_and_ordinary_files_are_read() {
    for path in ["app/src/lang/en.yaml", "README.md", "assets/app.css", "spec/x_spec.rb"] {
        assert!(!skips("aws-access-token", path));
        assert!(!skips("private-key", path));
    }
    for path in [
        "",
        ".env",
        "api/example.env",
        "config/database.yml",
        "src/app.js",
        "src/language_server.rs",
        "lib/msf/core/auxiliary/ubiquiti.rb",
        "backend/test.sh",
        "src/contest.py",
        "deploy/latest-release.js",
        "db/modules_metadata_base.json",
        "docker-compose.yml",
    ] {
        assert!(!skips("generic-password", path), "generic-password skips {path}");
        assert!(!skips("generic-api-key", path), "generic-api-key skips {path}");
    }
}
