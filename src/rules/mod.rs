mod architecture;
mod bundle_size;
mod crypto_weak;
mod dom_access;
mod eval;
mod flaky_test;
mod generated_file;
mod hardcoded_secrets;
mod http_resource;
mod naming;
mod open_redirect;
mod raw_html;
mod security;
mod sensitive_file;
mod sensitive_logging;
mod sync_io;
mod test_assertion;
mod test_location;
mod transaction;

use crate::config::Config;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::Deserialize;

pub(crate) mod rule_id {
    pub const SENSITIVE_FILE: &str = "sensitive-file";
    pub const ARCHITECTURE: &str = "architecture";
    pub const NAMING_CONVENTION: &str = "naming-convention";
    pub const TRANSACTION_BOUNDARY: &str = "transaction-boundary";
    pub const SECURITY: &str = "security";
    pub const CRYPTO_WEAK: &str = "crypto-weak";
    pub const GENERATED_FILE: &str = "generated-file";
    pub const TEST_LOCATION: &str = "test-location";
    pub const DOM_ACCESS: &str = "dom-access";
    pub const SYNC_IO: &str = "sync-io";
    pub const BUNDLE_SIZE: &str = "bundle-size";
    pub const TEST_ASSERTION: &str = "test-assertion";
    pub const FLAKY_TEST: &str = "flaky-test";
    pub const SENSITIVE_LOGGING: &str = "sensitive-logging";
    pub const EVAL: &str = "eval";
    pub const HARDCODED_SECRET: &str = "hardcoded-secret";
    pub const HTTP_RESOURCE: &str = "http-resource";
    pub const RAW_HTML: &str = "raw-html";
    pub const OPEN_REDIRECT: &str = "open-redirect";
}

pub static RE_JS_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(tsx?|jsx?)$").expect("RE_JS_FILE: invalid regex"));

pub static RE_TEST_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(test|spec)\.[jt]sx?$").expect("RE_TEST_FILE: invalid regex"));

pub static RE_ALL_FILES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r".").expect("RE_ALL_FILES: invalid regex"));

/// Matches single-line comment markers.
/// For JSDoc block comments, only matches `* ` (with space) or bare `*` lines
/// to avoid false positives on multiplication like `x * y`.
#[inline]
fn is_line_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//") || trimmed.starts_with("* ") || trimmed == "*"
}

/// Returns (1-based line number, line) pairs, skipping comment lines.
/// Tracks `/* ... */` block comment state across lines.
///
/// Known limitation: `/*` and `*/` inside string literals are treated as
/// comment markers, which may cause incorrect filtering in rare cases.
pub(crate) fn non_comment_lines(content: &str) -> Vec<(u32, &str)> {
    let mut result = Vec::new();
    let mut in_block = false;
    for (idx, line) in content.lines().enumerate() {
        let trimmed = line.trim_start();
        if in_block {
            if let Some(pos) = trimmed.find("*/") {
                in_block = false;
                let after = trimmed[pos + 2..].trim();
                if !after.is_empty() && !is_line_comment(after) {
                    result.push(((idx + 1) as u32, line));
                }
            }
            continue;
        }
        if let Some(pos) = trimmed.find("/*") {
            let before = trimmed[..pos].trim();
            if !trimmed[pos..].contains("*/") {
                in_block = true;
                if !before.is_empty() {
                    result.push(((idx + 1) as u32, line));
                }
                continue;
            }
            // Inline block comment like `code /* comment */ code`
            if before.is_empty() && trimmed[pos..].ends_with("*/") {
                continue;
            }
        }
        if is_line_comment(line) {
            continue;
        }
        result.push(((idx + 1) as u32, line));
    }
    result
}

pub fn find_non_comment_match(content: &str, pattern: &Regex) -> Option<u32> {
    non_comment_lines(content)
        .into_iter()
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| line_num)
}

pub fn count_non_comment_matches(content: &str, pattern: &Regex) -> usize {
    non_comment_lines(content)
        .into_iter()
        .filter(|(_, line)| pattern.is_match(line))
        .count()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Clone)]
pub struct Violation {
    pub rule: String,
    pub severity: Severity,
    pub failure: String,
    pub file: String,
    pub line: Option<u32>,
}

type Checker = Box<dyn Fn(&str, &str) -> Vec<Violation> + Send + Sync>;

pub struct Rule {
    pub file_pattern: Regex,
    checker: Checker,
}

impl Rule {
    pub fn check(&self, content: &str, file_path: &str) -> Vec<Violation> {
        (self.checker)(content, file_path)
    }
}

macro_rules! register_rules {
    ($config:expr, $rules:expr, $( $field:ident => $module:ident ),* $(,)?) => {
        $(if $config.rules.$field { $rules.push($module::rule()); })*
    };
}

pub fn load_rules(config: &Config) -> Vec<Rule> {
    let mut rules = Vec::new();
    register_rules!(config, rules,
        sensitive_file    => sensitive_file,
        architecture      => architecture,
        naming            => naming,
        transaction       => transaction,
        security          => security,
        crypto_weak       => crypto_weak,
        generated_file    => generated_file,
        test_location     => test_location,
        dom_access        => dom_access,
        sync_io           => sync_io,
        bundle_size       => bundle_size,
        test_assertion    => test_assertion,
        flaky_test        => flaky_test,
        sensitive_logging => sensitive_logging,
        eval              => eval,
        hardcoded_secrets => hardcoded_secrets,
        http_resource     => http_resource,
        raw_html          => raw_html,
        open_redirect     => open_redirect,
    );
    rules
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_line_comments_filtered() {
        let content = "code\n// comment\nmore code";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more code")]);
    }

    #[test]
    fn jsdoc_star_lines_filtered() {
        let content = "code\n * jsdoc line\n *\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn block_comment_single_line() {
        let content = "code\n/* inline comment */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (3, "more")]);
    }

    #[test]
    fn block_comment_body_without_star_prefix() {
        // This was the INT-001 bug: body lines without `* ` prefix leaked through
        let content =
            "let x = 1;\n/*\nThis line has no star prefix\nNeither does this one\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (6, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_before_open() {
        let content = "let x = 1; /*\ncomment body\n*/\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1; /*"), (4, "let y = 2;")]);
    }

    #[test]
    fn block_comment_with_code_after_close() {
        let content = "/*\ncomment\n*/ let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(3, "*/ let x = 1;"), (4, "let y = 2;")]);
    }

    #[test]
    fn nested_style_block_comments() {
        // Nested block comments are not supported; matches first */
        let content = "code\n/* outer\n/* inner */\nmore";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "code"), (4, "more")]);
    }

    #[test]
    fn empty_content() {
        let lines: Vec<_> = non_comment_lines("");
        assert!(lines.is_empty());
    }

    #[test]
    fn no_comments() {
        let content = "let x = 1;\nlet y = 2;";
        let lines: Vec<_> = non_comment_lines(content);
        assert_eq!(lines, vec![(1, "let x = 1;"), (2, "let y = 2;")]);
    }

    #[test]
    fn find_non_comment_match_skips_block_comments() {
        let re = Regex::new(r"TODO").unwrap();
        let content = "/*\nTODO: fix this\n*/\nlet x = 1;";
        assert_eq!(find_non_comment_match(content, &re), None);
    }

    #[test]
    fn count_non_comment_matches_skips_block_comments() {
        let re = Regex::new(r"unsafe").unwrap();
        let content = "/*\nunsafe block\nunsafe fn\n*/\nunsafe { real }";
        assert_eq!(count_non_comment_matches(content, &re), 1);
    }
}
