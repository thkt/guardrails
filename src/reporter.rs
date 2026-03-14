use crate::rules::Violation;

fn format_rule_name(rule: &str) -> (String, &'static str) {
    if rule.starts_with("biome/") {
        let short = rule.strip_prefix("biome/lint/").unwrap_or(rule);
        let name = short.rsplit('/').next().unwrap_or(short);
        (name.to_string(), "biome")
    } else if rule.starts_with("oxlint/") {
        let name = rule.strip_prefix("oxlint/").unwrap_or(rule);
        (name.to_string(), "oxlint")
    } else {
        (rule.to_string(), "guardrails")
    }
}

pub fn format_violations(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![
        format!(
            "GUARDRAILS: {} issues blocked this operation",
            violations.len()
        ),
        String::new(),
    ];

    for (i, v) in violations.iter().enumerate() {
        let (rule_name, source) = format_rule_name(&v.rule);
        let location = match v.line {
            Some(l) => format!("{}:{}", v.file, l),
            None => v.file.clone(),
        };

        lines.push(format!(
            "[{}] {} ({}) [{}]",
            i + 1,
            rule_name,
            source,
            v.severity
        ));
        lines.push(format!("    location: {}", location));
        lines.push(format!("    fix: {}", v.fix));
        lines.push(String::new());
    }

    lines.push("Fix the issues above and retry.".to_string());

    lines.join("\n")
}

pub fn format_warnings(violations: &[&Violation]) -> String {
    if violations.is_empty() {
        return String::new();
    }

    let mut lines = vec![format!("GUARDRAILS: {} warnings", violations.len())];

    for v in violations {
        let (rule_name, source) = format_rule_name(&v.rule);
        let location = match v.line {
            Some(l) => format!("{}:{}", v.file, l),
            None => v.file.clone(),
        };
        lines.push(format!(
            "  - {} ({}) [{}] at {}",
            rule_name, source, v.severity, location
        ));
        lines.push(format!("    fix: {}", v.fix));
    }

    lines.push(String::new());

    lines.join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Severity;

    #[test]
    fn format_rule_name_biome() {
        let (name, source) = format_rule_name("biome/lint/suspicious/noExplicitAny");
        assert_eq!(name, "noExplicitAny");
        assert_eq!(source, "biome");
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
    fn format_violations_output() {
        let v = Violation {
            rule: "oxlint/eslint(no-debugger)".to_string(),
            severity: Severity::High,
            fix: "Remove debugger".to_string(),
            file: "/src/app.ts".to_string(),
            line: Some(5),
        };
        let output = format_violations(&[&v]);
        assert!(output.contains("eslint(no-debugger) (oxlint) [HIGH]"));
        assert!(output.contains("/src/app.ts:5"));
    }

    #[test]
    fn format_warnings_output() {
        let v = Violation {
            rule: "biome/lint/style/useConst".to_string(),
            severity: Severity::Low,
            fix: "Use const".to_string(),
            file: "/src/app.ts".to_string(),
            line: Some(10),
        };
        let output = format_warnings(&[&v]);
        assert!(output.contains("useConst (biome) [LOW]"));
        assert!(output.contains("fix: Use const"));
    }
}
