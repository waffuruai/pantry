//! Where wpantry's data comes from: one file per remote API or list, each
//! cached and refetched only when stale. A source that can't be reached
//! with nothing cached is `Offline`, so the check that asked reports
//! "not checked" instead of clean. The checks that judge this data are in
//! [`crate::checks`].

pub mod breaches;
pub mod distros;
pub mod endoflife;
pub mod extensions;
pub mod fetch;
pub mod file;
pub mod hash_lookups;
pub mod indicator_lists;
pub mod kev;
pub mod malicious_packages;
#[cfg(test)]
mod mutate;
pub mod osv;
pub mod package_licenses;
pub mod releases;
#[cfg(test)]
pub(crate) mod testing;
