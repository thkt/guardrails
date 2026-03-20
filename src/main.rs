mod ast;
mod ast_security;
mod biome;
mod config;
mod oxlint;
mod parse_json;
mod reporter;
mod resolve;
mod rules;
mod scanner;
mod tempfile_util;

use config::Config;
use reporter::{format_violations, format_warnings};
use rules::{non_comment_lines, Violation, RE_JS_FILE};
use std::io::{self, Read};

const MAX_INPUT_SIZE: u64 = 10_000_000;

mod tool_name {
    pub const WRITE: &str = "Write";
    pub const EDIT: &str = "Edit";
    pub const MULTI_EDIT: &str = "MultiEdit";
}

#[derive(serde::Deserialize)]
struct ToolInput {
    tool_name: String,
    tool_input: ToolInputData,
}

#[derive(serde::Deserialize)]
struct ToolInputData {
    file_path: Option<String>,
    content: Option<String>,
    new_string: Option<String>,
    edits: Option<Vec<EditItem>>,
}

#[derive(serde::Deserialize)]
struct EditItem {
    new_string: Option<String>,
}

fn get_file_and_content(input: &ToolInput) -> Option<(String, String)> {
    let file_path = input.tool_input.file_path.clone()?;

    let content = match input.tool_name.as_str() {
        tool_name::WRITE => input.tool_input.content.clone()?,
        tool_name::EDIT => input.tool_input.new_string.clone()?,
        tool_name::MULTI_EDIT => {
            let edits = input.tool_input.edits.as_ref()?;
            edits
                .iter()
                .filter_map(|e| e.new_string.clone())
                .collect::<Vec<_>>()
                .join("\n")
        }
        _ => {
            if input.tool_input.content.is_some() || input.tool_input.new_string.is_some() {
                eprintln!(
                    "guardrails: unknown tool '{}' has content fields — add to get_file_and_content if it writes files",
                    input.tool_name
                );
            }
            return None;
        }
    };

    if file_path.is_empty() || content.is_empty() {
        return None;
    }

    Some((file_path, content))
}

fn collect_violations(file_path: &str, content: &str, config: &Config) -> Vec<Violation> {
    let mut violations = Vec::new();
    let is_js = RE_JS_FILE.is_match(file_path);

    // Priority: oxlint first (faster), biome as fallback. Only one runs per check.
    if is_js {
        let mut linted = false;
        if config.rules.oxlint {
            if let Some(bin) = oxlint::resolve(file_path) {
                if let Some(results) = oxlint::check(content, file_path, &bin) {
                    violations.extend(results);
                    linted = true;
                }
            }
        }
        if !linted && config.rules.biome {
            if let Some(bin) = biome::resolve(file_path) {
                violations.extend(biome::check(content, file_path, &bin));
            }
        }
    }

    let lines = non_comment_lines(content);
    let rules = rules::load_rules(config);
    for rule in &rules {
        if !rule.file_pattern.is_match(file_path) {
            continue;
        }
        violations.extend(rule.check(content, file_path, &lines));
    }

    let has_ast_rules = config.rules.ast_security || config.rules.no_use_effect;
    if is_js && has_ast_rules {
        let ast_violations =
            ast::with_parsed_program(content, file_path, |program, line_offsets| {
                let mut found = Vec::new();
                if config.rules.ast_security {
                    if let Some(v) = ast_security::check_bidi(content, file_path, line_offsets) {
                        found.push(v);
                    }
                    found.extend(ast_security::check_program(
                        program,
                        line_offsets,
                        file_path,
                    ));
                }
                if config.rules.no_use_effect {
                    found.extend(rules::no_use_effect::check_program(
                        program,
                        line_offsets,
                        file_path,
                    ));
                }
                found
            });
        if let Some(v) = ast_violations {
            violations.extend(v);
        }
    }

    violations
}

fn partition_violations<'a>(
    violations: &'a [Violation],
    config: &Config,
) -> (Vec<&'a Violation>, Vec<&'a Violation>) {
    violations
        .iter()
        .partition(|v| config.severity.block_on.contains(&v.severity))
}

fn main() {
    let mut input_str = String::new();
    let bytes_read = match io::stdin()
        .take(MAX_INPUT_SIZE + 1)
        .read_to_string(&mut input_str)
    {
        Ok(n) => n,
        Err(e) => {
            eprintln!("guardrails: failed to read stdin: {}", e);
            std::process::exit(1);
        }
    };

    // Fail-closed on truncation: oversized input cannot be reliably checked.
    if bytes_read as u64 > MAX_INPUT_SIZE {
        eprintln!(
            "guardrails: input too large (>{} bytes), blocking as precaution",
            MAX_INPUT_SIZE
        );
        std::process::exit(2);
    }

    let input: ToolInput = match serde_json::from_str(&input_str) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("guardrails: invalid JSON input: {}", e);
            std::process::exit(1);
        }
    };

    let Some((file_path, content)) = get_file_and_content(&input) else {
        eprintln!(
            "guardrails: skipping {} (unsupported or empty)",
            input.tool_name
        );
        std::process::exit(0);
    };

    let config = match Config::default().with_project_overrides(&file_path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("guardrails: config error (using defaults): {}", e);
            Config::default()
        }
    };

    if !config.enabled {
        std::process::exit(0);
    }

    let violations = collect_violations(&file_path, &content, &config);
    let (blocking, warnings) = partition_violations(&violations, &config);

    if !warnings.is_empty() {
        eprintln!("{}", format_warnings(&warnings));
    }

    if !blocking.is_empty() {
        eprintln!("{}", format_violations(&blocking));
        std::process::exit(2);
    }

    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;
    use rules::Severity;

    fn make_write_input(file_path: Option<&str>, content: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::WRITE.to_string(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: content.map(String::from),
                new_string: None,
                edits: None,
            },
        }
    }

    fn make_edit_input(file_path: Option<&str>, new_string: Option<&str>) -> ToolInput {
        ToolInput {
            tool_name: tool_name::EDIT.to_string(),
            tool_input: ToolInputData {
                file_path: file_path.map(String::from),
                content: None,
                new_string: new_string.map(String::from),
                edits: None,
            },
        }
    }

    fn make_violation(rule: &str, severity: Severity) -> Violation {
        Violation {
            rule: rule.to_string(),
            severity,
            fix: "fix".to_string(),
            file: "/test.ts".to_string(),
            line: Some(1),
        }
    }

    // --- get_file_and_content ---

    #[test]
    fn write_extracts_content() {
        let input = make_write_input(Some("/src/app.ts"), Some("const x = 1;"));
        let (path, content) = get_file_and_content(&input).unwrap();
        assert_eq!(path, "/src/app.ts");
        assert_eq!(content, "const x = 1;");
    }

    #[test]
    fn edit_extracts_new_string() {
        let input = make_edit_input(Some("/src/app.ts"), Some("const y = 2;"));
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "const y = 2;");
    }

    #[test]
    fn multi_edit_joins_edits() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_string(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_string()),
                content: None,
                new_string: None,
                edits: Some(vec![
                    EditItem {
                        new_string: Some("line1".to_string()),
                    },
                    EditItem {
                        new_string: Some("line2".to_string()),
                    },
                ]),
            },
        };
        let (_, content) = get_file_and_content(&input).unwrap();
        assert_eq!(content, "line1\nline2");
    }

    #[test]
    fn multi_edit_empty_edits_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_string(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_string()),
                content: None,
                new_string: None,
                edits: Some(vec![]),
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn multi_edit_all_none_returns_none() {
        let input = ToolInput {
            tool_name: tool_name::MULTI_EDIT.to_string(),
            tool_input: ToolInputData {
                file_path: Some("/src/app.ts".to_string()),
                content: None,
                new_string: None,
                edits: Some(vec![
                    EditItem { new_string: None },
                    EditItem { new_string: None },
                ]),
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn unsupported_tool_returns_none() {
        let input = ToolInput {
            tool_name: "Bash".to_string(),
            tool_input: ToolInputData {
                file_path: Some("/tmp/x".to_string()),
                content: Some("echo hi".to_string()),
                new_string: None,
                edits: None,
            },
        };
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn empty_path_returns_none() {
        let input = make_write_input(Some(""), Some("content"));
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn empty_content_returns_none() {
        let input = make_write_input(Some("/src/app.ts"), Some(""));
        assert!(get_file_and_content(&input).is_none());
    }

    #[test]
    fn missing_path_returns_none() {
        let input = make_write_input(None, Some("content"));
        assert!(get_file_and_content(&input).is_none());
    }

    // --- collect_violations ---

    #[test]
    fn collect_violations_detects_eval() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "eval(userInput);", &config);
        assert!(violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_clean_code() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "export function main() {}\n", &config);
        assert!(
            violations.is_empty(),
            "unexpected violations: {:?}",
            violations
        );
    }

    #[test]
    fn collect_violations_disabled_rule_skipped() {
        let mut config = Config::default();
        config.rules.eval = false;
        let violations = collect_violations("/src/app.ts", "eval(userInput);", &config);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_non_js_skips_js_rules() {
        let config = Config::default();
        let violations = collect_violations("/README.md", "eval(userInput);", &config);
        assert!(!violations.iter().any(|v| v.rule == "eval"));
    }

    #[test]
    fn collect_violations_ast_security_detects_injection() {
        let config = Config::default();
        let violations = collect_violations("/src/app.ts", "exec(userInput);", &config);
        assert!(violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_ast_security_disabled() {
        let mut config = Config::default();
        config.rules.ast_security = false;
        let violations = collect_violations("/src/app.ts", "exec(userInput);", &config);
        assert!(!violations
            .iter()
            .any(|v| v.rule == "child-process-injection"));
    }

    #[test]
    fn collect_violations_no_use_effect_detects_in_tsx() {
        let config = Config::default();
        let violations = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
        );
        assert!(violations.iter().any(|v| v.rule == "no-use-effect"));
    }

    #[test]
    fn collect_violations_no_use_effect_disabled() {
        let mut config = Config::default();
        config.rules.no_use_effect = false;
        let violations = collect_violations(
            "/src/App.tsx",
            "useEffect(() => { fetchData(); }, []);",
            &config,
        );
        assert!(!violations.iter().any(|v| v.rule == "no-use-effect"));
    }

    // --- partition_violations ---

    #[test]
    fn partition_high_blocks_by_default() {
        let config = Config::default();
        let violations = vec![make_violation("test", Severity::High)];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert_eq!(blocking.len(), 1);
        assert!(warnings.is_empty());
    }

    #[test]
    fn partition_medium_warns_by_default() {
        let config = Config::default();
        let violations = vec![make_violation("test", Severity::Medium)];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert!(blocking.is_empty());
        assert_eq!(warnings.len(), 1);
    }

    #[test]
    fn partition_critical_blocks_by_default() {
        let config = Config::default();
        let violations = vec![make_violation("test", Severity::Critical)];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert_eq!(blocking.len(), 1);
        assert!(warnings.is_empty());
    }

    #[test]
    fn partition_custom_block_on() {
        let mut config = Config::default();
        config.severity.block_on = vec![Severity::Medium];
        let violations = vec![
            make_violation("high-rule", Severity::High),
            make_violation("medium-rule", Severity::Medium),
        ];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert_eq!(blocking.len(), 1);
        assert_eq!(blocking[0].rule, "medium-rule");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].rule, "high-rule");
    }

    #[test]
    fn partition_empty_violations() {
        let config = Config::default();
        let violations: Vec<Violation> = vec![];
        let (blocking, warnings) = partition_violations(&violations, &config);
        assert!(blocking.is_empty());
        assert!(warnings.is_empty());
    }
}
