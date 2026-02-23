mod architecture;
mod bundle_size;
mod cargo_lock;
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
mod todo_macro;
mod transaction;
mod unsafe_usage;
mod unwrap_usage;

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
    pub const UNSAFE_USAGE: &str = "unsafe-usage";
    pub const UNWRAP_USAGE: &str = "unwrap-usage";
    pub const TODO_MACRO: &str = "todo-macro";
    pub const CARGO_LOCK: &str = "cargo-lock";
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

pub static RE_RS_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.rs$").expect("RE_RS_FILE: invalid regex"));

pub static RE_ALL_FILES: Lazy<Regex> =
    Lazy::new(|| Regex::new(r".").expect("RE_ALL_FILES: invalid regex"));

/// Matches comment-start markers, not inline comments.
/// For JSDoc block comments, only matches `* ` (with space) or bare `*` lines
/// to avoid false positives on multiplication like `x * y`.
#[inline]
fn starts_with_comment(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || trimmed.starts_with("/*")
        || trimmed.starts_with("* ")
        || trimmed == "*"
}

#[inline]
pub(crate) fn non_comment_lines(content: &str) -> impl Iterator<Item = (u32, &str)> {
    content
        .lines()
        .enumerate()
        .filter(|(_, line)| !starts_with_comment(line))
        .map(|(idx, line)| ((idx + 1) as u32, line))
}

pub fn find_non_comment_match(content: &str, pattern: &Regex) -> Option<u32> {
    non_comment_lines(content)
        .find(|(_, line)| pattern.is_match(line))
        .map(|(line_num, _)| line_num)
}

pub fn count_non_comment_matches(content: &str, pattern: &Regex) -> usize {
    non_comment_lines(content)
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
        unsafe_usage      => unsafe_usage,
        unwrap_usage      => unwrap_usage,
        todo_macro        => todo_macro,
        cargo_lock        => cargo_lock,
        eval              => eval,
        hardcoded_secrets => hardcoded_secrets,
        http_resource     => http_resource,
        raw_html          => raw_html,
        open_redirect     => open_redirect,
    );
    rules
}
