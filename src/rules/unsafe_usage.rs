use super::{non_comment_lines, Rule, Severity, Violation, RE_RS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_UNSAFE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\bunsafe\s+(?:\{|fn\s|impl\s)").expect("RE_UNSAFE"));

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_RS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            non_comment_lines(content)
                .into_iter()
                .filter(|(_, line)| RE_UNSAFE.is_match(line))
                .map(|(line_num, _)| Violation {
                    rule: super::rule_id::UNSAFE_USAGE.to_string(),
                    severity: Severity::Medium,
                    failure:
                        "Avoid unsafe blocks/fn/impl. Use safe abstractions or add a safety comment."
                            .to_string(),
                    file: file_path.to_string(),
                    line: Some(line_num),
                })
                .collect()
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
    fn detects_unsafe_block() {
        assert_eq!(
            check("fn main() {\n    unsafe {\n        *ptr = 42;\n    }\n}").len(),
            1
        );
    }

    #[test]
    fn detects_unsafe_fn() {
        assert_eq!(check("unsafe fn dangerous() {}").len(), 1);
    }

    #[test]
    fn detects_unsafe_impl() {
        assert_eq!(check("unsafe impl Send for Foo {}").len(), 1);
    }

    #[test]
    fn allows_safe_code() {
        assert!(check("fn main() { let x = 42; }").is_empty());
    }

    #[test]
    fn ignores_unsafe_in_comments() {
        assert!(check("// unsafe { *ptr = 42; }\nfn safe() {}").is_empty());
    }
}
