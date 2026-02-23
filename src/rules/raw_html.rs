use super::{non_comment_lines, Rule, Severity, Violation, RE_JS_FILE};
use once_cell::sync::Lazy;
use regex::Regex;

// HTML tag + string concatenation with variable: '<tag>' + identifier
static RE_HTML_CONCAT: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r#"['"]<[a-zA-Z][^>]*>['"]\s*\+\s*[a-zA-Z_$]"#)
        .expect("RE_HTML_CONCAT: invalid regex")
});

// Template literal with HTML tag and interpolation: `<tag>${...}</tag>`
static RE_HTML_TEMPLATE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"`[^`]{0,500}<[a-zA-Z][^>]{0,200}>[^`]{0,500}\$\{[^`]{0,500}`")
        .expect("RE_HTML_TEMPLATE: invalid regex")
});

// Array with HTML tags joined: .join(...) on same or adjacent line as HTML tag
static RE_HTML_JOIN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r#"['"]<[a-zA-Z][^>]*>['"]"#).expect("RE_HTML_JOIN: invalid regex"));
static RE_JOIN_CALL: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\.join\s*\(").expect("RE_JOIN_CALL: invalid regex"));

const JOIN_PROXIMITY_LINES: u32 = 5;

fn make_violation(file_path: &str, line_num: u32) -> Violation {
    Violation {
        rule: super::rule_id::RAW_HTML.to_string(),
        severity: Severity::High,
        failure: "Use DOM APIs or framework templating instead of HTML string concatenation."
            .to_string(),
        file: file_path.to_string(),
        line: Some(line_num),
    }
}

pub fn rule() -> Rule {
    Rule {
        file_pattern: RE_JS_FILE.clone(),
        checker: Box::new(|content: &str, file_path: &str| {
            let mut violations = Vec::new();
            let mut html_tag_line: Option<u32> = None;

            for (line_num, line) in non_comment_lines(content) {
                // Pattern 1: HTML string concat with variable
                if RE_HTML_CONCAT.is_match(line) {
                    violations.push(make_violation(file_path, line_num));
                    continue;
                }

                // Pattern 2: Template literal with HTML + interpolation
                if RE_HTML_TEMPLATE.is_match(line) {
                    violations.push(make_violation(file_path, line_num));
                    continue;
                }

                // Pattern 3: Array with HTML tags + .join() (within proximity)
                if RE_HTML_JOIN.is_match(line) {
                    html_tag_line = Some(line_num);
                }
                if let Some(tag_line) = html_tag_line {
                    if RE_JOIN_CALL.is_match(line)
                        && line_num.saturating_sub(tag_line) <= JOIN_PROXIMITY_LINES
                    {
                        violations.push(make_violation(file_path, line_num));
                        html_tag_line = None;
                    } else if line_num.saturating_sub(tag_line) > JOIN_PROXIMITY_LINES {
                        html_tag_line = None; // expired
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

    // T-021: '<div>' + userInput → 1 violation, High
    #[test]
    fn detects_html_concat_with_variable() {
        let v = check(r#"const html = '<div>' + userInput;"#, "/src/render.ts");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
    }

    // T-022: `<div>${variable}</div>` → 1 violation
    #[test]
    fn detects_template_literal_with_html() {
        let v = check("const html = `<div>${variable}</div>`;", "/src/render.ts");
        assert_eq!(v.len(), 1);
    }

    // T-023: parts.join('') with <div> → 1 violation
    #[test]
    fn detects_html_join() {
        let content = r#"const parts = ['<div>', userInput, '</div>'];
const html = parts.join('');"#;
        let v = check(content, "/src/render.ts");
        assert_eq!(v.len(), 1);
    }

    // T-024: '<div>' + '</div>' (literals only) → 0 violations
    #[test]
    fn allows_literal_only_concat() {
        assert!(check(r#"const html = '<div>' + '</div>';"#, "/src/render.ts").is_empty());
    }

    // T-025: // '<div>' + x (comment) → 0 violations
    #[test]
    fn ignores_comment() {
        assert!(check("// const html = '<div>' + x;", "/src/render.ts").is_empty());
    }

    // TB-001: distant .join() should NOT be flagged
    #[test]
    fn ignores_distant_join() {
        let mut lines = vec![r#"const tags = ['<br>'];"#.to_string()];
        for _ in 0..10 {
            lines.push("const x = doSomething();".to_string());
        }
        lines.push("const csv = values.join(',');".to_string());
        let content = lines.join("\n");
        assert!(
            check(&content, "/src/render.ts").is_empty(),
            "Distant .join() should not trigger false positive"
        );
    }

    // TB-002: multiline template literal (known limitation — not detected)
    #[test]
    fn multiline_template_not_detected() {
        let content = "const html = `\n  <div>\n    ${variable}\n  </div>\n`;";
        // Known limitation: multiline template literals are not detected
        // because regex requires backticks on the same line
        assert!(check(content, "/src/render.ts").is_empty());
    }
}
