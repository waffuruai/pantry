//! What every OS shares: the encrypted-DNS helpers ([`dns`]), the
//! developer-tool settings ([`dev_settings`]), and the persistence inventory
//! ([`persistence`]), which each OS extends with its own places.

pub mod dev_settings;
pub mod dns;
pub mod persistence;
