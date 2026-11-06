//! Markup that hides text from a reader: hidden elements and styles, and
//! comments.

// --- Hidden HTML ---------------------------------------------------------

const HIDE_MARKS: &[&str] = &[
    "display:none",
    "display: none",
    "visibility:hidden",
    "visibility: hidden",
    "opacity:0;",
    "opacity: 0;",
    "opacity:0\"",
    "opacity: 0\"",
    "opacity:0'",
    "opacity: 0'",
    "font-size:0",
    "font-size: 0",
    "font-size:1px",
    "font-size: 1px",
    "left:-9999",
    "left: -9999",
    "left:-10000",
    "top:-9999",
    "text-indent:-9999",
    "text-indent: -9999",
    "clip:rect(0",
    "clip: rect(0",
    "clip-path:inset(100%",
    "aria-hidden=\"true\"",
    "aria-hidden='true'",
];

fn css_value_white(tag: &str, prop: &str) -> bool {
    let mut rest = tag;
    while let Some(i) = rest.find(prop) {
        let before = &rest[..i];
        let after = &rest[i + prop.len()..];
        rest = after;
        if prop == "color" && before.ends_with("background-") {
            continue;
        }
        let v: String = after
            .trim_start()
            .trim_start_matches(':')
            .trim_start()
            .chars()
            .take_while(|c| *c != ';' && *c != '"' && *c != '\'')
            .collect();
        let v = v.trim();
        if ["#fff", "#ffffff", "white", "rgb(255,255,255)", "rgb(255, 255, 255)", "#fffffffff"].contains(&v)
            || v.starts_with("#fff ")
            || v.starts_with("white ")
        {
            return true;
        }
    }
    false
}

const HTML_ELEMENTS: &[&str] = &[
    "div",
    "span",
    "p",
    "section",
    "article",
    "aside",
    "footer",
    "header",
    "small",
    "font",
    "b",
    "i",
    "em",
    "strong",
    "a",
    "li",
    "ul",
    "ol",
    "td",
    "th",
    "tr",
    "table",
    "pre",
    "code",
    "details",
    "summary",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "label",
    "button",
    "iframe",
    "template",
    "dialog",
    "noscript",
    "nav",
    "main",
    "figure",
    "figcaption",
    "blockquote",
    "sup",
    "sub",
    "mark",
    "abbr",
    "address",
    "kbd",
    "samp",
    "var",
    "output",
    "svg",
    "g",
    "text",
    "textarea",
    "center",
    "u",
    "s",
    "del",
    "ins",
    "q",
    "dd",
    "dt",
    "dl",
];

/// Why this (lowercased) opening tag hides its content, if it does. Only
/// a real element on one line counts: markdown prose has `<` and `>` too.
fn hidden_tag(tag: &str) -> Option<&'static str> {
    let name: String = tag[1..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
    if !HTML_ELEMENTS.contains(&name.as_str()) || tag.contains('\n') || tag.len() > 600 {
        return None;
    }
    let after_name = tag[1 + name.len()..].chars().next().unwrap_or('>');
    if !(after_name.is_whitespace() || after_name == '>' || after_name == '/') {
        return None;
    }
    if let Some(m) = HIDE_MARKS.iter().find(|m| tag.contains(*m)) {
        return Some(match *m {
            m if m.starts_with("display") => "display:none",
            m if m.starts_with("visibility") => "visibility:hidden",
            m if m.starts_with("opacity") => "opacity:0",
            m if m.starts_with("font-size") => "a zero-size font",
            m if m.starts_with("aria") => "aria-hidden",
            _ => "positioned off screen",
        });
    }
    if tag.split_whitespace().skip(1).any(|a| {
        a == "hidden" || a == "hidden>" || a == "hidden/>" || a.starts_with("hidden=") || a.starts_with("hidden>")
    }) {
        return Some("the hidden attribute");
    }
    if css_value_white(tag, "color") && (css_value_white(tag, "background") || css_value_white(tag, "background-color"))
    {
        return Some("white on white");
    }
    None
}

fn strip_tags(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for c in s.chars() {
        match c {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if !in_tag => out.push(c),
            _ => {}
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Hidden elements holding a paragraph's worth of text: (line, text, how).
pub(crate) fn hidden_elements(text: &str) -> Vec<(usize, String, &'static str)> {
    let mut out = Vec::new();
    let lower = text.to_ascii_lowercase();
    let mut rest = 0usize;
    while let Some(i) = lower[rest..].find('<') {
        let start = rest + i;
        let Some(end_rel) = lower[start..].find('>') else { break };
        let end = start + end_rel;
        let tag = &lower[start..=end];
        rest = end + 1;
        if tag.starts_with("</") || tag.starts_with("<!") || tag.ends_with("/>") {
            continue;
        }
        let name: String = tag[1..].chars().take_while(|c| c.is_ascii_alphanumeric()).collect();
        if name.is_empty() {
            continue;
        }
        let Some(how) = hidden_tag(tag) else { continue };
        let close = format!("</{name}");
        let body_end = lower[rest..].find(&close).map(|c| rest + c).unwrap_or((rest + 4000).min(text.len()));
        let body_end = (body_end..=text.len()).find(|&b| text.is_char_boundary(b)).unwrap_or(text.len());
        let body = strip_tags(&text[rest..body_end]);
        if body.len() >= 40 && body.split_whitespace().count() >= 6 {
            out.push((text[..start].matches('\n').count() + 1, body, how));
        }
        if out.len() >= 20 {
            break;
        }
    }
    out
}

/// HTML comments (and markdown's `[//]: #` comment trick): (line, text).
pub(crate) fn html_comments(text: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut rest = 0usize;
    while let Some(i) = text[rest..].find("<!--") {
        let start = rest + i;
        let Some(end_rel) = text[start + 4..].find("-->") else { break };
        let end = start + 4 + end_rel;
        out.push((text[..start].matches('\n').count() + 1, strip_tags(&text[start + 4..end])));
        rest = end + 3;
        if out.len() >= 50 {
            break;
        }
    }
    for (n, line) in text.lines().enumerate() {
        let t = line.trim_start();
        if t.starts_with("[//]: #") || t.starts_with("[comment]: <>") || t.starts_with("[//]: <>") {
            out.push((n + 1, t.to_string()));
        }
    }
    out
}
