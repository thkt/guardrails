use crate::resolve::run_linter_check;
use crate::rules::{Severity, Violation};
use crate::scanner::{build_line_offsets, offset_to_line};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct BiomeOutput {
    diagnostics: Vec<BiomeDiagnostic>,
}

#[derive(Debug, Deserialize)]
struct BiomeDiagnostic {
    category: String,
    severity: String,
    description: String,
    advices: BiomeAdvices,
    location: BiomeLocation,
}

#[derive(Debug, Deserialize)]
struct BiomeAdvices {
    advices: Vec<BiomeAdvice>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum BiomeAdvice {
    Log {
        log: (String, Vec<BiomeMessagePart>),
    },
    #[allow(dead_code)]
    Other(serde_json::Value),
}

#[derive(Debug, Deserialize)]
struct BiomeMessagePart {
    content: String,
}

#[derive(Debug, Deserialize)]
struct BiomeLocation {
    span: Option<Vec<u32>>,
}

pub fn resolve(file_path: &str) -> Option<PathBuf> {
    crate::resolve::try_resolve_bin("biome", file_path)
}

pub fn check(content: &str, file_path: &str, bin: &Path) -> Option<Vec<Violation>> {
    let output: BiomeOutput = run_linter_check(
        content,
        file_path,
        bin,
        &["lint", "--reporter=json"],
        "biome",
    )?;
    Some(convert_diagnostics(output, content, file_path))
}

fn convert_diagnostics(output: BiomeOutput, content: &str, file_path: &str) -> Vec<Violation> {
    let line_offsets = build_line_offsets(content);

    output
        .diagnostics
        .into_iter()
        .map(|d| {
            let severity = Severity::from_linter_str(&d.severity);

            let line = d.location.span.as_ref().map(|span| {
                let offset = span.first().copied().unwrap_or(0) as usize;
                offset_to_line(&line_offsets, offset) as u32
            });

            let fix = get_fix_for_rule(&d.category)
                .map(String::from)
                .unwrap_or_else(|| extract_fix_from_advices(&d.advices, &d.description));

            Violation {
                rule: format!("biome/{}", d.category),
                severity,
                fix,
                file: file_path.to_string(),
                line,
            }
        })
        .collect()
}

fn get_fix_for_rule(category: &str) -> Option<&'static str> {
    match category {
        "lint/security/noGlobalEval" => {
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        }
        "lint/suspicious/noExplicitAny" => {
            Some("Use `unknown` with type guards, or define a specific type/interface")
        }
        "lint/suspicious/noDebugger" => Some("Remove debugger statement"),
        "lint/suspicious/noConsole" => Some("Remove console.log or use a proper logger"),
        "lint/correctness/noUnusedVariables" => {
            Some("Remove the variable, or prefix with _ if intentional")
        }
        "lint/correctness/noUnusedImports" => Some("Remove the unused import"),
        "lint/a11y/useAltText" => Some("Add alt attribute to img element"),
        "lint/a11y/useButtonType" => Some("Add type attribute to button element"),
        "lint/a11y/noBlankTarget" => {
            Some("Add rel=\"noopener noreferrer\" to links with target=\"_blank\"")
        }
        _ => None,
    }
}

fn extract_fix_from_advices(advices: &BiomeAdvices, fallback: &str) -> String {
    let texts: Vec<String> = advices
        .advices
        .iter()
        .filter_map(|advice| match advice {
            BiomeAdvice::Log { log: (_, parts) } => {
                let text: String = parts.iter().map(|p| p.content.as_str()).collect();
                if text.is_empty() {
                    None
                } else {
                    Some(text)
                }
            }
            BiomeAdvice::Other(_) => None,
        })
        .collect();

    if texts.is_empty() {
        fallback.to_string()
    } else {
        texts.join(" ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_fix_for_known_rule() {
        assert_eq!(
            get_fix_for_rule("lint/security/noGlobalEval"),
            Some("Use JSON.parse() for data, or restructure to avoid dynamic code execution")
        );
        assert_eq!(
            get_fix_for_rule("lint/suspicious/noExplicitAny"),
            Some("Use `unknown` with type guards, or define a specific type/interface")
        );
        assert_eq!(
            get_fix_for_rule("lint/a11y/useAltText"),
            Some("Add alt attribute to img element")
        );
    }

    #[test]
    fn get_fix_for_unknown_rule() {
        assert!(get_fix_for_rule("unknown/rule").is_none());
    }

    #[test]
    fn convert_diagnostics_maps_fields() {
        let content = "line1\nline2\nline3\n";
        let output = BiomeOutput {
            diagnostics: vec![BiomeDiagnostic {
                category: "lint/suspicious/noExplicitAny".to_string(),
                severity: "error".to_string(),
                description: "Unexpected any".to_string(),
                advices: BiomeAdvices { advices: vec![] },
                location: BiomeLocation {
                    span: Some(vec![6]), // offset 6 = line 2
                },
            }],
        };
        let violations = convert_diagnostics(output, content, "/src/app.ts");
        assert_eq!(violations.len(), 1);
        let v = &violations[0];
        assert_eq!(v.rule, "biome/lint/suspicious/noExplicitAny");
        assert_eq!(v.file, "/src/app.ts");
        assert_eq!(v.line, Some(2));
        assert_eq!(
            v.fix,
            "Use `unknown` with type guards, or define a specific type/interface"
        );
    }

    #[test]
    fn convert_diagnostics_with_no_span() {
        let output = BiomeOutput {
            diagnostics: vec![BiomeDiagnostic {
                category: "lint/unknown/rule".to_string(),
                severity: "warning".to_string(),
                description: "Some warning".to_string(),
                advices: BiomeAdvices { advices: vec![] },
                location: BiomeLocation { span: None },
            }],
        };
        let violations = convert_diagnostics(output, "content", "/src/app.ts");
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].line, None);
        assert_eq!(violations[0].fix, "Some warning");
    }

    #[test]
    fn extract_fix_from_empty_advices() {
        let advices = BiomeAdvices { advices: vec![] };
        let result = extract_fix_from_advices(&advices, "fallback message");
        assert_eq!(result, "fallback message");
    }

    #[test]
    fn extract_fix_from_log_advice() {
        let advices = BiomeAdvices {
            advices: vec![BiomeAdvice::Log {
                log: (
                    "info".to_string(),
                    vec![BiomeMessagePart {
                        content: "Fix suggestion".to_string(),
                    }],
                ),
            }],
        };
        let result = extract_fix_from_advices(&advices, "fallback");
        assert_eq!(result, "Fix suggestion");
    }
}
