//! What every part of wpantry leans on and none of it owns: files and
//! paths ([`files`]), running programs ([`process`]), the OS ([`os`]),
//! threads ([`parallel`]), temporary directories ([`temp`]), Homebrew's
//! layout ([`homebrew`]), HTTP behind the host allowlist ([`net`]), and the
//! in-tree readers and algorithms the dependency policy keeps out of
//! crates: [`json`], [`plist`], [`re`], [`sha256`], and crypto wallet
//! [`addresses`].

pub mod addresses;
pub mod archive;
pub mod dates;
pub mod files;
pub mod homebrew;
pub mod json;
pub mod net;
pub mod os;
pub mod parallel;
pub mod plist;
pub mod process;
pub mod re;
pub mod sha256;
pub mod temp;
pub mod toml;
pub mod walk;
