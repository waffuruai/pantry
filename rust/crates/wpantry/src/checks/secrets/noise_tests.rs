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
fn provider_rules_ordinary_files_and_env_files_are_read() {
    for path in ["app/src/lang/en.yaml", "README.md", "assets/app.css", "spec/x_spec.rb"] {
        assert!(!skips("aws-access-token", path));
        assert!(!skips("private-key", path));
    }
    for path in [
        "",
        ".env",
        "docs/.env.production",
        "locales/.npmrc",
        "api/example.env",
        "config/database.yml",
        "src/app.js",
        "src/language_server.rs",
        "spec/lib/client_spec.rb",
        "backend/test.sh",
        "db/modules_metadata_base.json",
        "docker-compose.yml",
    ] {
        assert!(!skips("generic-password", path), "generic-password skips {path}");
        assert!(!skips("generic-api-key", path), "generic-api-key skips {path}");
    }
}

#[test]
fn env_and_credential_files_and_their_templates() {
    for path in [
        ".env",
        "backend/.env.local",
        "deploy/prod.env",
        ".envrc",
        ".npmrc",
        "home/.netrc",
        ".aws/credentials",
        "android/key.properties",
        "config/secrets.yml",
        "config/database.yml",
        "infra/prod.tfvars",
    ] {
        assert_eq!(secret_file(path), Some(true), "{path}");
    }
    for path in [".env.example", "api/example.env", "backend/.env.template", ".env.sample", "config/database.yml.dist"]
    {
        assert_eq!(secret_file(path), Some(false), "{path}");
    }
    for path in ["api/src/env.ts", "src/environment.ts", "config/app.yml", "messages_de.properties", "envoy.yaml"] {
        assert_eq!(secret_file(path), None, "{path}");
    }
}

#[test]
fn a_test_is_any_folder_or_file_named_for_tests() {
    for path in [
        "backend/tests/unit/test_speaker_sample.py",
        "apps/AppStandalone/integration_test/test.dart",
        "e2e-tests/config.ts",
        "tests-blackbox/common/config.ts",
        "pkg/auth/login_test.go",
        "api/src/websocket/authenticate.test.ts",
        "vendor/symfony/validator/Tests/Constraints/UrlValidatorTest.php",
        "src/HttpClientTestCase.php",
        "spec/lib/rex/proto/sms/client_spec.rb",
        "e2e/login-spec.js",
        "web/__mocks__/api.js",
        "lib/net/ssh.rb.ut.rb",
        "backend/test.sh",
        "testing/helpers.go",
    ] {
        assert!(test(path), "{path}");
    }
    for path in [
        "src/contest.py",
        "deploy/latest-release.js",
        "lib/attestation.rb",
        "pytest.ini",
        "packages/specs/src/preset.yaml",
        "spec.rb",
        "src/app.js",
    ] {
        assert!(!test(path), "{path}");
    }
}

#[test]
fn vendored_code_is_someone_elses() {
    for path in [
        "vendor/slim/slim/Slim/Http/Uri.php",
        "web/node_modules/x/index.js",
        "third_party/abseil/x.cc",
        "lib/gemcache/ruby/1.9.1/gems/authlogic-3.1.0/README.rdoc",
        "vendor/bundle/ruby/3.2.0/gems/rack/lib/rack.rb",
        "venv/lib/python3.12/site-packages/requests/auth.py",
        "ios/Pods/Firebase/x.m",
    ] {
        assert!(vendored(path), "{path}");
    }
    for path in ["src/vendors.ts", "lib/msf/core/vendor_mixin.rb", "app/models/vendor.rb"] {
        assert!(!vendored(path), "{path}");
    }
}

#[test]
fn commented_out_examples_but_not_real_values_or_references() {
    for (line, secret) in [
        ("# DB_PASSWORD=\"secret\"", "secret"),
        ("  # adminPassword: strongpassword", "strongpassword"),
        ("// password: 'my$ecret'", "my$ecret"),
        ("-- password = 'admin'", "admin"),
        ("; password=changeme", "changeme"),
    ] {
        assert!(commented_example(line.as_bytes(), secret.as_bytes()), "{line}");
    }
    for (line, secret) in [
        ("# password: \"Tr0ub4dor&3xq\"", "Tr0ub4dor&3xq"),
        ("#   --docker-password='QUAY_DG_PASSWORD'", "QUAY_DG_PASSWORD"),
        ("# PASSWORD=${VAULT_PASSWORD}", "${VAULT_PASSWORD}"),
        ("password = \"secret\"", "secret"),
        ("x = 1 # password: secret", "secret"),
    ] {
        assert!(!commented_example(line.as_bytes(), secret.as_bytes()), "{line}");
    }
}
