//! What every OS shares: the encrypted-DNS helpers ([`dns`]), the
//! developer-tool checks ([`tools`]), and the persistence inventory
//! ([`persistence`]), which each OS extends with its own places.

pub mod dns;
pub mod persistence;
pub mod tools;
