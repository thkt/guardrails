use super::{non_comment_lines, Rule, Severity, Violation, RE_RS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

static RE_TODO_MACRO: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(todo|unimplemented)!\s*\(").expect("RE_TODO_MACRO"));

/// Computes test-context line ranges by tracking #[test], #[cfg(test)], and `mod tests`.
/// Known limitation: brace counting is naive and does not account for braces inside
/// string literals or comments. This may cause incorrect range boundaries in rare cases.
fn test_context_ranges(content: &str) -> Vec<(u32, u32)> {
    let mut ranges = Vec::new();
    let mut in_test = false;
    let mut brace_depth: i32 = 0;
    let mut test_start = 0u32;

    for (idx, line) in content.lines().enumerate() {
        let line_num = (idx + 1) as u32;
        let trimmed = line.trim();

        if !in_test
            && (trimmed.starts_with("#[test]")
                || trimmed.starts_with("#[cfg(test)]")
                || trimmed.contains("mod tests"))
        {
            in_test = true;
            test_start = line_num;
            brace_depth = 0;
        }

        if in_test {
            for ch in trimmed.chars() {
                if ch == '{' {
                    brace_depth += 1;
                } else if ch == '}' {
                    brace_depth -= 1;
                    if brace_depth <= 0 {
                        ranges.push((test_start, line_num));
                        in_test = false;
                        break;
                    }
                }
            }
        }
    }

    if in_test {
        let line_count = content.lines().count() as u32;
        ranges.push((test_start, line_count));
    }

    ranges
}

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_RS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let test_ranges = test_context_ranges(content);
            non_comment_lines(content)
                .into_iter()
                .filter(|(_, line)| RE_TODO_MACRO.is_match(line))
                .filter(|(line_num, _)| {
                    !test_ranges
                        .iter()
                        .any(|(start, end)| *line_num >= *start && *line_num <= *end)
                })
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
