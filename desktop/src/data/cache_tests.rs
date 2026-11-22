use super::*;

#[test]
fn cache_path_matches_the_scanner() {
    let env = |pairs: &'static [(&'static str, &'static str)]| {
        move |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| *key == name)
                .map(|(_, value)| value.into())
        }
    };
    assert_eq!(
        cache_path_from(&env(&[("WPANTRY_DB", "/x/w.db"), ("HOME", "/h")])),
        PathBuf::from("/x/w.db")
    );
    assert_eq!(
        cache_path_from(&env(&[("HOME", "/h")])),
        PathBuf::from("/h/.cache/wpantry/wpantry.db")
    );
}
