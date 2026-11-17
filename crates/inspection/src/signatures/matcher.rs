//! Aho-Corasick matching across UTF-8, UTF-16LE, dotted and fullwidth pattern variants.

use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};

const EXCERPT_RADIUS: usize = 40;
const FULLWIDTH_OFFSET: u32 = 0xFEE0;
const IDEOGRAPHIC_SPACE: char = '\u{3000}';

/// The signature record a pattern belongs to, as an index into its database table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Subject {
    Client(usize),
    Module(usize),
    Rule(usize),
}

#[derive(Clone, Copy, Debug, Default)]
pub struct Settings {
    pub case_insensitive: bool,
    /// Rejects matches embedded inside a longer lowercase word.
    pub boundary: bool,
    /// Adds fullwidth Unicode variants (`Ａｕｔｏ`) of ASCII patterns.
    pub fullwidth: bool,
}

/// A verified match within a haystack.
#[derive(Clone, Copy, Debug)]
pub struct Hit<'a> {
    pub subject: Subject,
    pub label: &'a str,
    pub start: usize,
    pub end: usize,
}

struct Pattern {
    subject: Subject,
    label: Box<str>,
    width: usize,
}

/// Multi-pattern matcher compiled once per signature table.
///
/// ```
/// use inspection::signatures::{Matcher, Settings, Subject};
///
/// let matcher = Matcher::new([(Subject::Client(0), "net/wurstclient")], Settings::default());
/// let mut hits = 0;
/// matcher.scan(b"class net.wurstclient.WurstClient", |_| hits += 1);
/// assert_eq!(hits, 1);
/// ```
pub struct Matcher {
    automaton: AhoCorasick,
    patterns: Vec<Pattern>,
    settings: Settings,
    longest: usize,
}

impl Matcher {
    pub fn new<'a>(
        entries: impl IntoIterator<Item = (Subject, &'a str)>,
        settings: Settings,
    ) -> Self {
        let mut needles: Vec<Vec<u8>> = Vec::new();
        let mut patterns = Vec::new();
        for (subject, text) in entries {
            let mut variants = vec![text.to_owned()];
            if text.contains('/') {
                variants.push(text.replace('/', "."));
            }
            if settings.fullwidth && text.is_ascii() {
                variants.push(fullwidth(text));
            }
            for variant in variants {
                let utf16 = variant.encode_utf16().flat_map(u16::to_le_bytes).collect();
                for (bytes, width) in [(variant.into_bytes(), 1), (utf16, 2)] {
                    needles.push(bytes);
                    patterns.push(Pattern {
                        subject,
                        label: text.into(),
                        width,
                    });
                }
            }
        }
        let longest = needles.iter().map(Vec::len).max().unwrap_or(0);
        let automaton = AhoCorasickBuilder::new()
            .ascii_case_insensitive(settings.case_insensitive)
            .match_kind(MatchKind::LeftmostFirst)
            .build(&needles)
            .expect("signature patterns are within automaton limits");
        Self {
            automaton,
            patterns,
            settings,
            longest,
        }
    }

    /// Length in bytes of the longest needle; scanners overlap chunks by this amount.
    pub fn longest(&self) -> usize {
        self.longest
    }

    pub fn scan<'a>(&'a self, haystack: &[u8], mut visit: impl FnMut(Hit<'a>)) {
        for found in self.automaton.find_iter(haystack) {
            let pattern = &self.patterns[found.pattern().as_usize()];
            let (start, end) = (found.start(), found.end());
            if self.settings.boundary && !bounded(haystack, start, end, pattern.width) {
                continue;
            }
            visit(Hit {
                subject: pattern.subject,
                label: &pattern.label,
                start,
                end,
            });
        }
    }
}

/// Printable context around a match, with UTF-16 padding removed.
pub fn excerpt(haystack: &[u8], start: usize, end: usize) -> String {
    let from = start.saturating_sub(EXCERPT_RADIUS);
    let to = (end + EXCERPT_RADIUS).min(haystack.len());
    String::from_utf8_lossy(&haystack[from..to])
        .chars()
        .filter(|character| *character != '\0')
        .map(|character| {
            if character.is_control() || character == char::REPLACEMENT_CHARACTER {
                '.'
            } else {
                character
            }
        })
        .collect()
}

fn fullwidth(text: &str) -> String {
    text.chars()
        .map(|character| match character {
            ' ' => IDEOGRAPHIC_SPACE,
            '!'..='~' => char::from_u32(character as u32 + FULLWIDTH_OFFSET).unwrap_or(character),
            _ => character,
        })
        .collect()
}

fn bounded(haystack: &[u8], start: usize, end: usize, width: usize) -> bool {
    let character = |index: usize| -> Option<u8> {
        let low = *haystack.get(index)?;
        (width == 1 || haystack.get(index + 1) == Some(&0)).then_some(low)
    };
    let first = haystack[start];
    let last = haystack[end - width];
    let start_ok = start < width
        || character(start - width).is_none_or(|previous| {
            !previous.is_ascii_alphanumeric()
                || (!previous.is_ascii_uppercase() && first.is_ascii_uppercase())
        });
    let end_ok = character(end).is_none_or(|next| {
        !next.is_ascii_alphanumeric() || (next.is_ascii_uppercase() && !last.is_ascii_uppercase())
    });
    start_ok && end_ok
}
