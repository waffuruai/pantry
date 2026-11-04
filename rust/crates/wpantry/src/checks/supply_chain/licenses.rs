//! Dependency licenses (`--licenses`): each locked package's
//! declared licenses, judged against an allowlist of SPDX ids. A package
//! passes when its license expression can be satisfied with allowed ids
//! (`MIT OR GPL-3.0-only` passes an allowlist holding MIT); one with no
//! identifiable license is only counted. deps.dev's `non-standard` (custom
//! terms, such as a license that needs a company licence) is a license no
//! allowlist holds, so it is reported, not counted as unknown.
//! The declared licenses come from [`crate::sources::deps_dev`].

/// Whether an SPDX license expression can be satisfied with `allowed` ids:
/// OR needs one side, AND both; `X WITH exception` is judged as X; ids
/// compare case-insensitively, and `X+` (or-later) as X.
pub fn satisfied(expr: &str, allowed: &[String]) -> Option<bool> {
    let spaced = expr.replace('(', " ( ").replace(')', " ) ");
    let tokens: Vec<&str> = spaced.split_whitespace().collect();
    let mut i = 0;
    let v = or(&tokens, &mut i, allowed)?;
    (i == tokens.len()).then_some(v)
}

fn or(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = and(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("OR")) {
        *i += 1;
        let rhs = and(t, i, allowed)?;
        v = v || rhs;
    }
    Some(v)
}

fn and(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let mut v = atom(t, i, allowed)?;
    while t.get(*i).is_some_and(|w| w.eq_ignore_ascii_case("AND")) {
        *i += 1;
        let rhs = atom(t, i, allowed)?;
        v = v && rhs;
    }
    Some(v)
}

fn atom(t: &[&str], i: &mut usize, allowed: &[String]) -> Option<bool> {
    let w = *t.get(*i)?;
    *i += 1;
    if w == "(" {
        let v = or(t, i, allowed)?;
        if t.get(*i) != Some(&")") {
            return None;
        }
        *i += 1;
        return Some(v);
    }
    if w == ")" || w.eq_ignore_ascii_case("AND") || w.eq_ignore_ascii_case("OR") {
        return None;
    }
    if t.get(*i).is_some_and(|x| x.eq_ignore_ascii_case("WITH")) {
        *i += 2; // the exception doesn't change which license it is
    }
    let id = w.trim_end_matches('+');
    Some(allowed.iter().any(|a| a.eq_ignore_ascii_case(id)))
}

/// One package's verdict: None passes, Some(["UNKNOWN"]) has no license we
/// can judge, Some(ids) are the licenses outside the allowlist.
pub fn judge(licenses: &[String], allowed: &[String]) -> Option<Vec<String>> {
    if licenses.is_empty() {
        return Some(vec!["UNKNOWN".into()]);
    }
    // deps.dev lists one expression per declared license; any one passing is enough.
    let mut verdicts = licenses.iter().map(|l| satisfied(l, allowed));
    if verdicts.any(|v| v == Some(true)) {
        return None;
    }
    if licenses.iter().all(|l| satisfied(l, allowed).is_none()) {
        return Some(vec!["UNKNOWN".into()]);
    }
    Some(licenses.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sources::testing::ids;

    #[test]
    fn spdx_expressions() {
        let allow = ids(&["MIT", "Apache-2.0", "BSD-3-Clause"]);
        assert_eq!(satisfied("MIT", &allow), Some(true));
        assert_eq!(satisfied("mit", &allow), Some(true));
        assert_eq!(satisfied("MIT OR GPL-3.0-only", &allow), Some(true));
        assert_eq!(satisfied("MIT AND GPL-3.0-only", &allow), Some(false));
        assert_eq!(satisfied("(Apache-2.0 OR MIT) AND BSD-3-Clause", &allow), Some(true));
        assert_eq!(satisfied("Apache-2.0 WITH LLVM-exception", &allow), Some(true));
        assert_eq!(satisfied("GPL-2.0+", &allow), Some(false));
        assert_eq!(satisfied("MIT AND", &allow), None);
        assert_eq!(judge(&[], &allow), Some(ids(&["UNKNOWN"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only"]), &allow), Some(ids(&["GPL-3.0-only"])));
        assert_eq!(judge(&ids(&["GPL-3.0-only", "MIT"]), &allow), None);
        assert_eq!(judge(&ids(&["non-standard"]), &allow), Some(ids(&["non-standard"])), "custom terms need review");
    }
}
