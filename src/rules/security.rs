use super::{non_comment_lines, Rule, Severity, Violation, RE_ALL_FILES, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_HTML_FILE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.(jsx?|tsx?|html?)$").expect("RE_HTML_FILE: invalid regex"));

static RE_DOC_WRITE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"document\.write\s*\(").expect("RE_DOC_WRITE: invalid regex"));
// Match innerHTML/outerHTML assignment to non-literal values (exclude string literals)
static RE_INNER_HTML: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\.innerHTML\s*=\s*[^"'`\s;]"#).expect("RE_INNER_HTML: invalid regex")
});
static RE_OUTER_HTML: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\.outerHTML\s*=\s*[^"'`\s;]"#).expect("RE_OUTER_HTML: invalid regex")
});
static RE_SET_TIMEOUT_STR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"setTimeout\s*\(\s*['"`]"#).expect("RE_SET_TIMEOUT_STR: invalid regex")
});
static RE_SET_INTERVAL_STR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"setInterval\s*\(\s*['"`]"#).expect("RE_SET_INTERVAL_STR: invalid regex")
});
static RE_POST_MESSAGE_STAR: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"\.postMessage\s*\([^,]+,\s*['"`]\*['"`]\s*\)"#)
        .expect("RE_POST_MESSAGE_STAR: invalid regex")
});
static RE_LOCAL_STORAGE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"localStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#)
        .expect("RE_LOCAL_STORAGE_SENSITIVE: invalid regex")
});
static RE_SESSION_STORAGE_SENSITIVE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"sessionStorage\.(setItem|getItem)\s*\(\s*['"`](token|password|secret|key|auth|credential)"#)
        .expect("RE_SESSION_STORAGE_SENSITIVE: invalid regex")
});

struct SecurityIssue {
    pattern: &'static Lazy<Regex>,
    file_pattern: &'static Lazy<Regex>,
    failure: &'static str,
    severity: Severity,
}

static SECURITY_ISSUES: [SecurityIssue; 8] = [
    SecurityIssue {
        pattern: &RE_DOC_WRITE,
        file_pattern: &RE_HTML_FILE,
        failure: "Use createElement/appendChild instead",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_INNER_HTML,
        file_pattern: &RE_HTML_FILE,
        failure: "Use textContent or DOMPurify.sanitize() instead",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_SET_TIMEOUT_STR,
        file_pattern: &RE_JS_FILE,
        failure: "Use function reference: setTimeout(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_SET_INTERVAL_STR,
        file_pattern: &RE_JS_FILE,
        failure: "Use function reference: setInterval(() => { ... }, delay)",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_POST_MESSAGE_STAR,
        file_pattern: &RE_JS_FILE,
        failure: "Specify exact target origin instead of '*'",
        severity: Severity::High,
    },
    SecurityIssue {
        pattern: &RE_OUTER_HTML,
        file_pattern: &RE_HTML_FILE,
        failure: "Use DOM methods instead",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_LOCAL_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        failure: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
    SecurityIssue {
        pattern: &RE_SESSION_STORAGE_SENSITIVE,
        file_pattern: &RE_JS_FILE,
        failure: "Use httpOnly cookies for sensitive data",
        severity: Severity::Medium,
    },
];

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_ALL_FILES.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for issue in SECURITY_ISSUES.iter() {
                if !issue.file_pattern.is_match(file_path) {
                    continue;
                }
                for (line_num, line) in non_comment_lines(content) {
                    if issue.pattern.is_match(line) {
                        violations.push(Violation {
                            rule: super::rule_id::SECURITY.to_string(),
                            severity: issue.severity,
                            failure: issue.failure.to_string(),
                            file: file_path.to_string(),
                            line: Some(line_num),
                        });
                    }
                }
            }

            violations
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str, path: &str) -> Vec<Violation> {
        rule().check(content, path)
    }

    #[test]
    fn detects_html_injection() {
        let inner = "el.innerHTML = x;";
        let outer = "el.outerHTML = x;";
        assert!(!check(inner, "/src/component.tsx").is_empty());
        assert!(!check(outer, "/src/component.tsx").is_empty());
    }

    #[test]
    fn detects_code_injection() {
        let cases = ["setTimeout('alert(1)', 100);", "setInterval('fn()', 1000);"];
        for content in cases {
            assert_eq!(check(content, "/src/utils.ts").len(), 1);
        }
    }

    #[test]
    fn detects_insecure_postmessage() {
        let content = r#"window.postMessage(data, '*');"#;
        assert_eq!(check(content, "/src/messenger.ts").len(), 1);
    }

    #[test]
    fn detects_sensitive_storage() {
        let cases = [
            "localStorage.setItem('token', jwt);",
            "sessionStorage.setItem('password', p);",
        ];
        for content in cases {
            assert_eq!(check(content, "/src/auth.ts").len(), 1);
        }
    }

    #[test]
    fn allows_safe_patterns() {
        let cases = [
            ("el.textContent = userInput;", "/src/component.tsx"),
            ("setTimeout(() => fn(), 100);", "/src/utils.ts"),
            ("localStorage.setItem('theme', 'dark');", "/src/utils.ts"),
        ];
        for (content, path) in cases {
            assert!(check(content, path).is_empty());
        }
    }

    // FR-006: innerHTML/outerHTML string literal exclusion
    #[test]
    fn allows_innerhtml_string_literal() {
        // T-032: el.innerHTML = "<div>static</div>" should NOT be flagged
        let content = r#"el.innerHTML = "<div>static</div>";"#;
        assert!(
            check(content, "/src/component.tsx").is_empty(),
            "String literal innerHTML should not be flagged"
        );
    }

    #[test]
    fn detects_innerhtml_variable() {
        // T-033: el.innerHTML = variable should still be flagged
        let content = "el.innerHTML = variable;";
        assert!(
            !check(content, "/src/component.tsx").is_empty(),
            "Variable innerHTML should be flagged"
        );
    }

    #[test]
    fn allows_outerhtml_string_literal() {
        // T-034: el.outerHTML = "..." should NOT be flagged
        let content = r#"el.outerHTML = "<span>text</span>";"#;
        assert!(
            check(content, "/src/component.tsx").is_empty(),
            "String literal outerHTML should not be flagged"
        );
    }

    #[test]
    fn detects_outerhtml_variable() {
        // T-035: el.outerHTML = variable should still be flagged
        let content = "el.outerHTML = variable;";
        assert!(
            !check(content, "/src/component.tsx").is_empty(),
            "Variable outerHTML should be flagged"
        );
    }

    // TC-001: dedicated document.write() detection test
    #[test]
    fn detects_document_write() {
        let v = check("document.write(userInput);", "/src/render.tsx");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert!(v[0].failure.contains("createElement"));
    }

    // SEC-003: innerHTML bypass via "" + variable (known limitation)
    #[test]
    fn innerhtml_empty_string_concat_not_detected() {
        // Known limitation: `"" + variable` starts with quote, so regex excludes it
        let content = r#"el.innerHTML = "" + userInput;"#;
        assert!(
            check(content, "/src/component.tsx").is_empty(),
            "Known limitation: empty string concat bypasses detection"
        );
    }
}
