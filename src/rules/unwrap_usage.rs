use super::{
    is_in_test_context, non_comment_lines, test_context_ranges, Rule, Severity, Violation,
    RE_RS_FILE,
};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_UNWRAP: Lazy<Regex> = Lazy::new(|| Regex::new(r"\.unwrap\(\)").expect("RE_UNWRAP"));

const THRESHOLD: usize = 3;

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_RS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let test_ranges = test_context_ranges(content);
            let unwrap_lines: Vec<(u32, &str)> = non_comment_lines(content)
                .into_iter()
                .filter(|(_, line)| RE_UNWRAP.is_match(line))
                .filter(|(line_num, _)| !is_in_test_context(*line_num, &test_ranges))
                .collect();
            if unwrap_lines.len() >= THRESHOLD {
                return unwrap_lines
                    .iter()
                    .map(|(line_num, _)| Violation {
                        rule: super::rule_id::UNWRAP_USAGE.to_string(),
                        severity: Severity::Medium,
                        failure: format!(
                            "Excessive .unwrap() usage ({} total, threshold: {}). Use ? operator or proper error handling.",
                            unwrap_lines.len(), THRESHOLD
                        ),
                        file: file_path.to_string(),
                        line: Some(*line_num),
                    })
                    .collect();
            }
            Vec::new()
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(content: &str) -> Vec<Violation> {
        rule().check(content, "/src/main.rs")
    }

    #[test]
    fn detects_excessive_unwrap() {
        let content = "fn main() {\n    a.unwrap();\n    b.unwrap();\n    c.unwrap();\n}";
        let v = check(content);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].line, Some(2));
        assert_eq!(v[1].line, Some(3));
        assert_eq!(v[2].line, Some(4));
    }

    #[test]
    fn allows_few_unwraps() {
        let content = "fn main() {\n    a.unwrap();\n    b.unwrap();\n}";
        assert!(check(content).is_empty());
    }

    #[test]
    fn ignores_unwrap_in_comments() {
        let content = "// a.unwrap()\n// b.unwrap()\n// c.unwrap()\nfn safe() {}";
        assert!(check(content).is_empty());
    }

    #[test]
    fn allows_unwrap_in_tests() {
        let content = "#[cfg(test)]\nmod tests {\n    fn t() {\n        a.unwrap();\n        b.unwrap();\n        c.unwrap();\n    }\n}";
        assert!(check(content).is_empty());
    }

    #[test]
    fn detects_unwrap_outside_tests() {
        let content = "fn prod() {\n    a.unwrap();\n    b.unwrap();\n    c.unwrap();\n}\n#[cfg(test)]\nmod tests {\n    fn t() { x.unwrap(); }\n}";
        let v = check(content);
        assert_eq!(v.len(), 3);
        assert_eq!(v[0].line, Some(2));
    }
}
