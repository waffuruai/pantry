//! Tokens of the YARA rule language.
//!
//! The lexer is a cursor the parser drives: hex strings (`{ 4D 5A ?? }`) and
//! regular expressions (`/ab+c/i`) can't be told from braces and operators
//! without knowing where in a rule the cursor is, so the parser asks for them
//! by name ([`Lexer::hex_body`]) and `/` always starts a regex (YARA divides
//! with `\`). Everything else is an ordinary token with the line it starts on,
//! for error messages.

use crate::Error;

/// One token.
#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    Ident(String),
    /// `$name`, `$name*` (a wildcard) or `$` alone (the current string in a loop).
    StrId(String),
    /// `#name` or `#`: a match count.
    StrCount(String),
    /// `@name` or `@`: a match offset.
    StrOffset(String),
    /// `!name` or `!`: a match length.
    StrLength(String),
    Int(i64),
    Float(f64),
    /// A text string literal, escapes resolved.
    Text(Vec<u8>),
    /// A regular expression literal: its source and its `i`/`s` flags.
    Regex {
        src: Vec<u8>,
        nocase: bool,
        dotall: bool,
    },
    Punct(&'static str),
    Eof,
}

/// Every punctuation token, longest first so `<<` wins over `<`.
const PUNCTS: &[&str] = &[
    "..", "<<", ">>", "==", "!=", "<=", ">=", "{", "}", "(", ")", "[", "]", ":", "=", ",", ".", "+", "-", "*", "\\",
    "%", "&", "|", "^", "~", "<", ">",
];

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: usize,
    peeked: Option<(Tok, usize)>,
}

impl<'a> Lexer<'a> {
    pub fn new(src: &'a str) -> Self {
        Lexer { src: src.as_bytes(), pos: 0, line: 1, peeked: None }
    }

    /// The line the next token starts on.
    pub fn line(&mut self) -> usize {
        match self.peek_with_line() {
            Ok((_, line)) => *line,
            Err(_) => self.line,
        }
    }

    pub fn peek(&mut self) -> Result<&Tok, Error> {
        Ok(&self.peek_with_line()?.0)
    }

    fn peek_with_line(&mut self) -> Result<&(Tok, usize), Error> {
        if self.peeked.is_none() {
            let tok = self.lex()?;
            self.peeked = Some(tok);
        }
        Ok(self.peeked.as_ref().expect("just filled"))
    }

    pub fn next(&mut self) -> Result<Tok, Error> {
        match self.peeked.take() {
            Some((tok, _)) => Ok(tok),
            None => Ok(self.lex()?.0),
        }
    }

    /// Step over one byte after a lexing error, so error recovery can't stall.
    pub fn skip_byte(&mut self) {
        self.peeked = None;
        if let Some(c) = self.src.get(self.pos) {
            if *c == b'\n' {
                self.line += 1;
            }
            self.pos += 1;
        }
    }

    pub fn err(&self, msg: impl Into<String>) -> Error {
        Error::Syntax { line: self.line, msg: msg.into() }
    }

    /// Skip spaces and both kinds of comment.
    fn skip_trivia(&mut self) -> Result<(), Error> {
        loop {
            match self.src.get(self.pos..self.pos + 2) {
                Some(b"//") => {
                    while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                }
                Some(b"/*") => {
                    let start = self.line;
                    self.pos += 2;
                    loop {
                        match self.src.get(self.pos..self.pos + 2) {
                            Some(b"*/") => {
                                self.pos += 2;
                                break;
                            }
                            Some(_) => {
                                if self.src[self.pos] == b'\n' {
                                    self.line += 1;
                                }
                                self.pos += 1;
                            }
                            None => return Err(Error::Syntax { line: start, msg: "unterminated comment".into() }),
                        }
                    }
                }
                _ => match self.src.get(self.pos) {
                    Some(b'\n') => {
                        self.line += 1;
                        self.pos += 1;
                    }
                    Some(c) if c.is_ascii_whitespace() => self.pos += 1,
                    _ => return Ok(()),
                },
            }
        }
    }

    fn lex(&mut self) -> Result<(Tok, usize), Error> {
        self.skip_trivia()?;
        let line = self.line;
        let Some(&c) = self.src.get(self.pos) else { return Ok((Tok::Eof, line)) };
        let tok = match c {
            b'"' => Tok::Text(self.text()?),
            b'/' => self.regex()?,
            b'$' | b'#' | b'@' => {
                self.pos += 1;
                let name = self.ident_chars();
                let wildcard = c == b'$' && self.src.get(self.pos) == Some(&b'*');
                if wildcard {
                    self.pos += 1;
                }
                let name = if wildcard { format!("{name}*") } else { name };
                match c {
                    b'$' => Tok::StrId(name),
                    b'#' => Tok::StrCount(name),
                    _ => Tok::StrOffset(name),
                }
            }
            b'!' if self.src.get(self.pos + 1) != Some(&b'=') => {
                self.pos += 1;
                Tok::StrLength(self.ident_chars())
            }
            b'0'..=b'9' => self.number()?,
            c if c == b'_' || c.is_ascii_alphabetic() => {
                let mut name = self.ident_chars();
                // `rule_*` in `any of (rule_*)`: a wildcard when the `*` is
                // glued to the name and closes the item, never a product.
                if self.src.get(self.pos) == Some(&b'*') {
                    let next = self.src[self.pos + 1..].iter().find(|c| !c.is_ascii_whitespace());
                    if matches!(next, Some(b',') | Some(b')')) {
                        self.pos += 1;
                        name.push('*');
                    }
                }
                Tok::Ident(name)
            }
            _ => {
                let rest = &self.src[self.pos..];
                let Some(p) = PUNCTS.iter().find(|p| rest.starts_with(p.as_bytes())) else {
                    return Err(self.err(format!("unexpected character {:?}", c as char)));
                };
                self.pos += p.len();
                Tok::Punct(p)
            }
        };
        Ok((tok, line))
    }

    fn ident_chars(&mut self) -> String {
        let start = self.pos;
        while self.src.get(self.pos).is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_') {
            self.pos += 1;
        }
        String::from_utf8_lossy(&self.src[start..self.pos]).into_owned()
    }

    /// An integer (decimal, `0x` hex or `0o` octal, with an optional `KB` or
    /// `MB` multiplier) or a float.
    fn number(&mut self) -> Result<Tok, Error> {
        let start = self.pos;
        let radix = match self.src.get(self.pos..self.pos + 2) {
            Some(b"0x") | Some(b"0X") => 16,
            Some(b"0o") => 8,
            _ => 10,
        };
        if radix != 10 {
            self.pos += 2;
        }
        let digits = self.pos;
        while self.src.get(self.pos).is_some_and(|c| c.is_ascii_hexdigit()) {
            self.pos += 1;
        }
        let is_float = radix == 10
            && self.src.get(self.pos) == Some(&b'.')
            && self.src.get(self.pos + 1).is_some_and(u8::is_ascii_digit);
        if is_float {
            self.pos += 1;
            while self.src.get(self.pos).is_some_and(u8::is_ascii_digit) {
                self.pos += 1;
            }
            let text = std::str::from_utf8(&self.src[start..self.pos]).expect("ascii");
            return text.parse().map(Tok::Float).map_err(|_| self.err(format!("bad number {text}")));
        }
        let text = std::str::from_utf8(&self.src[digits..self.pos]).expect("ascii");
        let mut value = i64::from_str_radix(text, radix)
            .map_err(|_| self.err(format!("bad number {}", String::from_utf8_lossy(&self.src[start..self.pos]))))?;
        match self.src.get(self.pos..self.pos + 2) {
            Some(b"KB") => {
                value = value.wrapping_mul(1024);
                self.pos += 2;
            }
            Some(b"MB") => {
                value = value.wrapping_mul(1024 * 1024);
                self.pos += 2;
            }
            _ => {}
        }
        Ok(Tok::Int(value))
    }

    /// A `"..."` literal with YARA's escapes: `\n \t \r \\ \" \xHH`.
    fn text(&mut self) -> Result<Vec<u8>, Error> {
        self.pos += 1;
        let mut out = Vec::new();
        loop {
            let Some(&c) = self.src.get(self.pos) else { return Err(self.err("unterminated string")) };
            self.pos += 1;
            match c {
                b'"' => return Ok(out),
                b'\n' => return Err(self.err("newline in string")),
                b'\\' => {
                    let Some(&e) = self.src.get(self.pos) else { return Err(self.err("unterminated string")) };
                    self.pos += 1;
                    out.push(match e {
                        b'n' => b'\n',
                        b't' => b'\t',
                        b'r' => b'\r',
                        b'\\' => b'\\',
                        b'"' => b'"',
                        b'x' => {
                            let hex = self.src.get(self.pos..self.pos + 2).ok_or_else(|| self.err("bad \\x escape"))?;
                            let byte = std::str::from_utf8(hex)
                                .ok()
                                .and_then(|h| u8::from_str_radix(h, 16).ok())
                                .ok_or_else(|| self.err("bad \\x escape"))?;
                            self.pos += 2;
                            byte
                        }
                        other => return Err(self.err(format!("unknown escape \\{}", other as char))),
                    });
                }
                _ => out.push(c),
            }
        }
    }

    /// `/source/flags`. The source is kept raw (escapes included) for the
    /// regex parser; only `\/` ends nothing.
    fn regex(&mut self) -> Result<Tok, Error> {
        self.pos += 1;
        let start = self.pos;
        loop {
            match self.src.get(self.pos) {
                None | Some(b'\n') => return Err(self.err("unterminated regular expression")),
                Some(b'\\') => self.pos += 2,
                Some(b'/') => break,
                Some(_) => self.pos += 1,
            }
        }
        let src = self.src[start..self.pos].to_vec();
        self.pos += 1;
        let (mut nocase, mut dotall) = (false, false);
        while let Some(&f) = self.src.get(self.pos) {
            match f {
                b'i' => nocase = true,
                b's' => dotall = true,
                _ => break,
            }
            self.pos += 1;
        }
        Ok(Tok::Regex { src, nocase, dotall })
    }

    /// The raw text of a hex string, up to (not including) its closing `}`.
    /// Called right after the parser consumed the opening `{`.
    pub fn hex_body(&mut self) -> Result<(String, usize), Error> {
        assert!(self.peeked.is_none(), "hex_body after a peek would skip a token");
        let line = self.line;
        let start = self.pos;
        let mut body = String::new();
        while let Some(&c) = self.src.get(self.pos) {
            match self.src.get(self.pos..self.pos + 2) {
                Some(b"//") => {
                    while self.pos < self.src.len() && self.src[self.pos] != b'\n' {
                        self.pos += 1;
                    }
                    continue;
                }
                Some(b"/*") => {
                    self.pos += 2;
                    while self.pos < self.src.len() && self.src.get(self.pos..self.pos + 2) != Some(b"*/") {
                        if self.src[self.pos] == b'\n' {
                            self.line += 1;
                        }
                        self.pos += 1;
                    }
                    self.pos += 2;
                    continue;
                }
                _ => {}
            }
            self.pos += 1;
            match c {
                b'}' => return Ok((body, line)),
                b'\n' => {
                    self.line += 1;
                    body.push(' ');
                }
                _ => body.push(c as char),
            }
        }
        self.pos = start;
        Err(Error::Syntax { line, msg: "unterminated hex string".into() })
    }
}

#[cfg(test)]
#[path = "lexer_tests.rs"]
mod tests;
