use super::{
    is_in_test_context, non_comment_lines, test_context_ranges, Rule, Severity, Violation,
    RE_RS_FILE,
};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_TODO_MACRO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(todo|unimplemented)!\s*\(").expect("RE_TODO_MACRO"));

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_RS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let test_ranges = test_context_ranges(content);
            non_comment_lines(content)
                .into_iter()
                .filter(|(_, line)| RE_TODO_MACRO.is_match(line))
                .filter(|(line_num, _)| !is_in_test_context(*line_num, &test_ranges))
                .map(|(line_num, _)| Violation {
                    rule: super::rule_id::TODO_MACRO.to_string(),
                    severity: Severity::Medium,
                    failure: "Remove todo!()/unimplemented!() before committing.".to_string(),
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
    fn detects_todo_in_production_code() {
        assert_eq!(check("fn process() {\n    todo!()\n}").len(), 1);
    }

    #[test]
    fn allows_todo_in_test() {
        assert!(check("#[test]\nfn test_something() {\n    todo!()\n}").is_empty());
    }

    #[test]
    fn allows_todo_in_test_module() {
        assert!(
            check("#[cfg(test)]\nmod tests {\n    fn helper() {\n        todo!()\n    }\n}")
                .is_empty()
        );
    }

    #[test]
    fn detects_todo_after_test_module() {
        let content = "#[cfg(test)]\nmod tests {\n    fn helper() { todo!() }\n}\n\nfn production() {\n    todo!()\n}";
        let v = check(content);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].line, Some(7));
    }

    #[test]
    fn ignores_todo_in_comments() {
        assert!(check("// todo!()\nfn safe() {}").is_empty());
    }
}
