//! Which CISA KEV entries name a product Pantry tracks by version: the
//! (`vendorProject`, `product`) pairs exactly as the catalog spells them.
//! Data only; `exploited` matches them. A product ending in `*` matches
//! every product that starts with what comes before the `*`.
//!
//! A component is named by what Pantry knows it by: `browser:<id>` (the
//! `BROWSERS` id in `apps.rs`), `app:<bundle id>` for a macOS app, and
//! `tool:<name>` for a `catalog.rs` tool. Only pairs the catalog uses are
//! listed; a product CISA lists under a broader name ("Multiple Products")
//! is left out, since it would match too much.
//!
//! TODO: Apple's macOS entries ("macOS", "iOS, iPadOS, and macOS") once the
//! Software Update check knows which release it is behind.

/// The pairs Chromium's own entries use; Chrome and every browser built
/// on Chromium carry them.
const CHROMIUM: Pairs = &[
    ("Google", "Chromium"),
    ("Google", "Chromium *"),
    // Chromium's graphics libraries, listed under their own names.
    ("Google", "Skia"),
    ("Google", "Dawn"),
];

/// Chromium's, plus the older entries CISA filed under Chrome's name.
const CHROME: Pairs = &[
    ("Google", "Chromium"),
    ("Google", "Chromium *"),
    ("Google", "Skia"),
    ("Google", "Dawn"),
    ("Google", "Chrome"),
    ("Google", "Chrome Blink"),
    ("Google", "Chrome FreeType"),
    ("Google", "Chrome Media"),
    ("Google", "Chrome WebAudio"),
];

const FIREFOX: Pairs = &[
    ("Mozilla", "Firefox"),
    ("Mozilla", "Firefox and Thunderbird"),
    ("Mozilla", "Firefox, Firefox ESR, and Thunderbird"),
];

const ACROBAT: Pairs = &[
    ("Adobe", "Acrobat"),
    ("Adobe", "Reader"),
    ("Adobe", "Acrobat and Reader"),
    ("Adobe", "Reader and Acrobat"),
    ("Adobe", "Acrobat and Reader, Flash Player"),
];

/// (`vendorProject`, `product`) pairs.
pub type Pairs = &'static [(&'static str, &'static str)];

/// (component, how the note names its entries, KEV pairs).
pub const PRODUCTS: &[(&str, &str, Pairs)] = &[
    ("browser:chrome", "Chromium", CHROME),
    ("browser:chromium", "Chromium", CHROMIUM),
    ("browser:edge", "Chromium", CHROMIUM),
    ("browser:brave", "Chromium", CHROMIUM),
    ("browser:arc", "Chromium", CHROMIUM),
    ("browser:opera", "Chromium", CHROMIUM),
    ("browser:vivaldi", "Chromium", CHROMIUM),
    ("browser:firefox", "Firefox", FIREFOX),
    ("browser:firefox-dev", "Firefox", FIREFOX),
    ("app:com.adobe.Reader", "Acrobat and Reader", ACROBAT),
    ("app:com.adobe.Acrobat.Pro", "Acrobat and Reader", ACROBAT),
    ("app:com.vmware.fusion", "VMware Fusion", &[("VMware", "ESXi, Workstation, and Fusion")]),
    (
        "tool:java",
        "Java SE",
        &[
            ("Oracle", "Java SE"),
            ("Oracle", "Java SE JDK and JRE"),
            ("Oracle", "Java SE and JRockit"),
            ("Oracle", "Java Runtime Environment (JRE)"),
        ],
    ),
    ("tool:php", "PHP", &[("PHP Group", "PHP"), ("PHP", "PHP"), ("PHP", "FastCGI Process Manager (FPM)")]),
    ("tool:openssl", "OpenSSL", &[("OpenSSL", "OpenSSL")]),
    ("tool:mongodb", "MongoDB", &[("MongoDB", "MongoDB and MongoDB Server")]),
];
