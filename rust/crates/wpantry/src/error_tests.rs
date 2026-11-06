use super::*;

#[test]
fn source_errors_are_unchecked_not_internal() {
    assert!(Error::Offline("x".into()).is_source());
    assert!(Error::Invalid("x".into()).is_source());
    assert!(Error::Failed("x".into()).is_source());
    assert!(!Error::Missing("x".into()).is_source());
    assert!(!Error::Io(std::io::Error::other("disk")).is_source());
}

#[test]
fn displays_the_underlying_message() {
    assert_eq!(Error::Missing("no gitleaks".into()).to_string(), "no gitleaks");
    let io: Error = std::io::Error::other("disk full").into();
    assert_eq!(io.to_string(), "disk full");
    let cache: Error = rusqlite::Error::InvalidQuery.into();
    assert!(matches!(cache, Error::Cache(_)));
    assert_eq!(cache.to_string(), rusqlite::Error::InvalidQuery.to_string());
}
