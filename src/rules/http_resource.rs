use super::{non_comment_lines, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_HTTP_URL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"["']http://[^"']+["']"#).expect("RE_HTTP_URL: invalid regex"));

static RE_LOCAL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"http://(localhost|127\.0\.0\.1)").expect("RE_LOCAL: invalid regex"));

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();

            for (line_num, line) in non_comment_lines(content) {
                for mat in RE_HTTP_URL.find_iter(line) {
                    let url_match = mat.as_str();
                    if !RE_LOCAL.is_match(url_match) {
                        violations.push(Violation {
                            rule: super::rule_id::HTTP_RESOURCE.to_string(),
                            severity: Severity::Medium,
                            failure: "Use HTTPS for external resources.".to_string(),
                            file: file_path.to_string(),
                            line: Some(line_num),
                        });
                        break;
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
        let r = rule();
        if !r.file_pattern.is_match(path) {
            return Vec::new();
        }
        r.check(content, path)
    }

    #[test]
    fn detects_http_fetch() {
        let v = check(r#"fetch("http://api.example.com/data");"#, "/src/api.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
    }

    #[test]
    fn detects_http_axios() {
        let v = check(
            r#"axios.get("http://cdn.example.com/lib.js");"#,
            "/src/api.ts",
        );
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn allows_localhost() {
        assert!(check(r#"fetch("http://localhost:3000/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn allows_loopback() {
        assert!(check(r#"fetch("http://127.0.0.1:8080/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn allows_https() {
        assert!(check(r#"fetch("https://api.example.com/data");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn ignores_comment() {
        assert!(check(r#"// fetch("http://x.com/api");"#, "/src/api.ts").is_empty());
    }

    #[test]
    fn detects_http_on_line_with_localhost() {
        let rule = rule();
        let content = r#"const urls = ["http://evil.com", "http://localhost:3000"];"#;
        let result = rule.check(content, "/src/api.ts");
        assert_eq!(result.len(), 1);
    }
}
