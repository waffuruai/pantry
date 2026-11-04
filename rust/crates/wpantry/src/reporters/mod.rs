//! How a scan is shown: the terminal report ([`text`]), the standalone HTML
//! report ([`html`]), the JSON envelope ([`json`]) and the JSON Lines
//! export ([`jsonl`]). Each renders the same findings; the CLI picks one
//! and prints it, and owns colour and the progress line.

pub mod html;
pub mod json;
pub mod jsonl;
pub mod text;
