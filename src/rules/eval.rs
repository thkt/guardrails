use super::{Rule, Severity, Violation, RE_JS_FILE};
use regex::Regex;
use std::sync::LazyLock;

static RE_EVAL_CALL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(^|[.\s(,;])eval\s*\(").expect("RE_EVAL_CALL: invalid regex"));

static RE_FUNCTION_CTOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(^|[\s(,;])(?:new\s+)?\bFunction\s*\(").expect("RE_FUNCTION_CTOR: invalid regex")
});

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|_content: &str, file_path: &str, lines: &[(u32, &str)]| {
            let mut violations = Vec::new();

            for &(line_num, line) in lines {
                if RE_EVAL_CALL.is_match(line) {
                    violations.push(Violation {
                        rule: super::rule_id::EVAL.to_owned(),
                        severity: Severity::High,
                        fix: "Avoid eval(). Use JSON.parse() for data or safe alternatives."
                            .to_owned(),
                        file: file_path.to_owned(),
                        line: Some(line_num),
                    });
                } else if RE_FUNCTION_CTOR.is_match(line) {
                    violations.push(Violation {
                        rule: super::rule_id::EVAL.to_owned(),
                        severity: Severity::High,
                        fix: "Avoid dynamic code generation with Function(). Use static functions."
                            .to_owned(),
                        file: file_path.to_owned(),
                        line: Some(line_num),
                    });
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
        r.check(content, path, &super::super::non_comment_lines(content))
    }

    #[test]
    fn detects_eval_call() {
        let v = check("eval(userInput);", "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    #[test]
    fn detects_new_function() {
        let v = check(r#"new Function("return " + x);"#, "/src/app.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    #[test]
    fn ignores_comment() {
        assert!(check("// eval(x);", "/src/app.ts").is_empty());
    }

    #[test]
    fn detects_window_eval() {
        assert_eq!(check("window.eval(x);", "/src/app.ts").len(), 1);
    }

    #[test]
    fn ignores_non_js_file() {
        assert!(check("eval(x);", "/docs/README.md").is_empty());
    }

    #[test]
    fn detects_bare_function_constructor() {
        let v = check(r#"Function("return " + x)();"#, "/src/app.ts");
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn detects_multiple_eval_calls() {
        let content = "eval(a);\neval(b);\neval(c);";
        let v = check(content, "/src/app.ts");
        assert_eq!(v.len(), 3);
    }

    #[test]
    fn new_function_message_is_specific() {
        let v = check(r#"new Function("return " + x);"#, "/src/app.ts");
        assert!(!v[0].fix.contains("eval()"));
    }

    #[test]
    fn ignores_callback_function() {
        assert!(check("callbackFunction(x)", "/src/app.ts").is_empty());
    }

    #[test]
    fn ignores_my_function() {
        assert!(check(" myFunction(x)", "/src/app.ts").is_empty());
    }
}
