use crate::color;
use crate::rules::Violation;

const HEADER_SEPARATOR: &str = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";
const FOOTER_SEPARATOR: &str = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━";

fn format_rule_name(rule: &str) -> (&str, &'static str) {
    match rule.strip_prefix("oxlint/") {
        Some(name) => (name, "oxlint"),
        None => (rule, "guardrails"),
    }
}

fn format_location(v: &Violation) -> String {
    match v.line {
        Some(l) => format!("{}:{}", v.file, l),
        None => v.file.clone(),
    }
}

pub fn format_violations(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![
        String::new(),
        color::bold_red(&format!("Guardrails {}", HEADER_SEPARATOR)),
    ];

    for v in violations {
        let (rule_name, source) = format_rule_name(&v.rule);
        lines.push(color::red(&format!(
            "  ✗ {} ({}) [{}]",
            rule_name, source, v.severity
        )));
        lines.push(format!("    {}", format_location(v)));
        lines.push(format!("    fix: {}", v.fix));
    }

    lines.push(color::bold_red(FOOTER_SEPARATOR));
    lines.push(color::bold_red(&format!(
        "BLOCKED: Fix {} issue{} in the source code and retry. Do not circumvent this check.",
        violations.len(),
        if violations.len() == 1 { "" } else { "s" }
    )));

    lines.join("\n")
}

pub fn format_warnings(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![
        String::new(),
        color::yellow(&format!(
            "Guardrails ⚠ {} warning{}",
            violations.len(),
            if violations.len() == 1 { "" } else { "s" }
        )),
    ];

    for v in violations {
        let (rule_name, source) = format_rule_name(&v.rule);
        lines.push(format!(
            "  - {} ({}) [{}] at {}",
            rule_name,
            source,
            v.severity,
            format_location(v)
        ));
        lines.push(format!("    fix: {}", v.fix));
    }

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::color::strip_ansi;
    use crate::rules::Severity;

    fn make_violation(rule: &str, severity: Severity, fix: &str) -> Violation {
        Violation {
            rule: rule.to_string(),
            severity,
            fix: fix.to_string(),
            file: "/src/app.ts".to_string(),
            line: Some(1),
        }
    }

    #[test]
    fn format_rule_name_oxlint() {
        let (name, source) = format_rule_name("oxlint/eslint(no-debugger)");
        assert_eq!(name, "eslint(no-debugger)");
        assert_eq!(source, "oxlint");
    }

    #[test]
    fn format_rule_name_guardrails() {
        let (name, source) = format_rule_name("security");
        assert_eq!(name, "security");
        assert_eq!(source, "guardrails");
    }

    #[test]
    fn format_violations_single_issue() {
        let v = make_violation(
            "oxlint/eslint(no-debugger)",
            Severity::High,
            "Remove debugger",
        );
        let output = strip_ansi(&format_violations(&[&v]));
        assert!(output.contains("Guardrails"), "missing header");
        assert!(output.contains("━"), "missing separator");
        assert!(output.contains("✗"), "missing cross mark");
        assert!(
            output.contains("eslint(no-debugger) (oxlint) [HIGH]"),
            "missing rule/source/severity"
        );
        assert!(output.contains("/src/app.ts:1"), "missing location");
        assert!(output.contains("fix: Remove debugger"), "missing fix");
        assert!(output.contains("BLOCKED"), "missing blocked footer");
    }

    #[test]
    fn format_violations_multiple_issues_count() {
        let v1 = make_violation("eval", Severity::High, "fix1");
        let v2 = make_violation("security", Severity::Critical, "fix2");
        let output = strip_ansi(&format_violations(&[&v1, &v2]));
        assert!(output.contains("2"));
    }

    #[test]
    fn format_warnings_contains_warning_symbol() {
        let v = make_violation(
            "oxlint/eslint(no-console)",
            Severity::Low,
            "Remove console.log",
        );
        let output = strip_ansi(&format_warnings(&[&v]));
        assert!(output.contains("Guardrails"));
        assert!(output.contains("⚠"));
        assert!(output.contains("eslint(no-console) (oxlint) [LOW]"));
        assert!(output.contains("fix: Remove console.log"));
    }
}
