use crate::rules::{rule_id, Severity, Violation};
use crate::scanner;
use oxc_allocator::Allocator;
use oxc_ast::ast::*;
use oxc_ast_visit::{walk, Visit};
use oxc_parser::Parser;
use oxc_span::SourceType;

const CHILD_PROCESS_FNS: [&str; 4] = ["exec", "execSync", "spawn", "spawnSync"];

/// Returns empty Vec on parse failure (fail-open).
pub fn check(content: &str, file_path: &str) -> Vec<Violation> {
    let Ok(source_type) = SourceType::from_path(file_path) else {
        eprintln!("guardrails: ast_security: unsupported file type: {file_path}");
        return Vec::new();
    };

    let allocator = Allocator::default();
    let ret = Parser::new(&allocator, content, source_type).parse();

    if ret.panicked {
        eprintln!("guardrails: ast_security: parser panicked on {file_path}");
        return Vec::new();
    }

    if !ret.errors.is_empty() {
        eprintln!(
            "guardrails: ast_security: {} parse error(s) in {file_path}, proceeding with partial AST",
            ret.errors.len(),
        );
    }

    let line_offsets = scanner::build_line_offsets(content);
    let mut visitor = SecurityVisitor {
        violations: Vec::new(),
        file_path,
        line_offsets: &line_offsets,
    };
    visitor.visit_program(&ret.program);
    visitor.violations
}

struct SecurityVisitor<'s> {
    violations: Vec<Violation>,
    file_path: &'s str,
    line_offsets: &'s [usize],
}

impl SecurityVisitor<'_> {
    fn span_to_line(&self, span: Span) -> u32 {
        scanner::offset_to_line(self.line_offsets, span.start as usize) as u32
    }

    fn push_violation(&mut self, rule: &str, severity: Severity, fix: &str, span: Span) {
        self.violations.push(Violation {
            rule: rule.to_string(),
            severity,
            fix: fix.to_string(),
            file: self.file_path.to_string(),
            line: Some(self.span_to_line(span)),
        });
    }

    fn check_err_stack(&mut self, call: &CallExpression) {
        if !is_response_call(&call.callee) {
            return;
        }
        for arg in &call.arguments {
            if arg_contains_stack(arg) {
                self.push_violation(
                    rule_id::ERR_STACK_EXPOSURE,
                    Severity::High,
                    "Use generic error message in production. Log stack trace server-side.",
                    call.span,
                );
                return;
            }
        }
    }

    fn check_child_process(&mut self, call: &CallExpression) {
        // KNOWN LIMITATION: aliased imports (import { exec as run }) are not detected.
        let name = match &call.callee {
            Expression::Identifier(id) => id.name.as_str(),
            Expression::StaticMemberExpression(sme) => sme.property.name.as_str(),
            Expression::ComputedMemberExpression(cme) => match &cme.expression {
                Expression::StringLiteral(s) => s.value.as_str(),
                _ => return,
            },
            _ => return,
        };
        if !CHILD_PROCESS_FNS.contains(&name) {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_string_literal_arg(first) {
            self.push_violation(
                rule_id::CHILD_PROCESS_INJECTION,
                Severity::High,
                "Use string literal for command. Validate and sanitize dynamic input.",
                call.span,
            );
        }
    }

    fn check_fs_path(&mut self, call: &CallExpression) {
        let obj = match &call.callee {
            Expression::StaticMemberExpression(sme) => &sme.object,
            // KNOWN LIMITATION: only bare `fs` identifier matched — aliased imports not detected.
            Expression::ComputedMemberExpression(cme) => match &cme.expression {
                Expression::StringLiteral(_) => &cme.object,
                _ => return,
            },
            _ => return,
        };
        if !is_ident(obj, "fs") {
            return;
        }
        let Some(first) = call.arguments.first() else {
            return;
        };
        if !is_safe_path_arg(first) {
            self.push_violation(
                rule_id::NON_LITERAL_FS_PATH,
                Severity::Medium,
                "Use string literal for file path. Validate against path traversal.",
                call.span,
            );
        }
    }
}

impl<'a> Visit<'a> for SecurityVisitor<'_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_err_stack(it);
        self.check_child_process(it);
        self.check_fs_path(it);
        walk::walk_call_expression(self, it);
    }
}

fn is_ident(expr: &Expression, name: &str) -> bool {
    matches!(expr, Expression::Identifier(id) if id.name == name)
}

/// Check if callee is res.json/res.send/res.status().json
fn is_response_call(callee: &Expression) -> bool {
    let (object, method) = match callee {
        Expression::StaticMemberExpression(sme) => (&sme.object, sme.property.name.as_str()),
        Expression::ComputedMemberExpression(cme) => match &cme.expression {
            Expression::StringLiteral(s) => (&cme.object, s.value.as_str()),
            _ => return false,
        },
        _ => return false,
    };
    if method != "json" && method != "send" {
        return false;
    }
    if is_ident(object, "res") || is_ident(object, "response") {
        return true;
    }
    let Expression::CallExpression(inner) = object else {
        return false;
    };
    let Expression::StaticMemberExpression(inner_sme) = &inner.callee else {
        return false;
    };
    inner_sme.property.name == "status"
        && (is_ident(&inner_sme.object, "res") || is_ident(&inner_sme.object, "response"))
}

fn arg_contains_stack(arg: &Argument) -> bool {
    match arg {
        Argument::SpreadElement(s) => expr_contains_stack(&s.argument),
        _ => arg.as_expression().is_some_and(|e| expr_contains_stack(e)),
    }
}

fn expr_contains_stack(expr: &Expression) -> bool {
    match expr {
        Expression::StaticMemberExpression(sme) => {
            sme.property.name == "stack" || expr_contains_stack(&sme.object)
        }
        Expression::ObjectExpression(obj) => obj.properties.iter().any(|p| match p {
            ObjectPropertyKind::ObjectProperty(op) => expr_contains_stack(&op.value),
            ObjectPropertyKind::SpreadProperty(sp) => expr_contains_stack(&sp.argument),
        }),
        Expression::CallExpression(call) => call.arguments.iter().any(|a| arg_contains_stack(a)),
        Expression::ConditionalExpression(ce) => {
            expr_contains_stack(&ce.consequent) || expr_contains_stack(&ce.alternate)
        }
        Expression::LogicalExpression(le) => {
            expr_contains_stack(&le.left) || expr_contains_stack(&le.right)
        }
        Expression::ArrayExpression(arr) => arr.elements.iter().any(|el| match el {
            ArrayExpressionElement::SpreadElement(s) => expr_contains_stack(&s.argument),
            ArrayExpressionElement::Elision(_) => false,
            _ => el.as_expression().is_some_and(expr_contains_stack),
        }),
        Expression::TemplateLiteral(tl) => tl.expressions.iter().any(|e| expr_contains_stack(e)),
        _ => false,
    }
}

fn is_string_literal_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg.as_expression().is_some_and(is_static_template_literal),
    }
}

fn is_safe_path_arg(arg: &Argument) -> bool {
    match arg {
        Argument::StringLiteral(_) => true,
        _ => arg.as_expression().is_some_and(is_static_path),
    }
}

fn is_static_template_literal(expr: &Expression) -> bool {
    matches!(expr, Expression::TemplateLiteral(tl) if tl.expressions.is_empty())
}

fn is_static_path(expr: &Expression) -> bool {
    match expr {
        Expression::StringLiteral(_) => true,
        _ if is_static_template_literal(expr) => true,
        Expression::Identifier(id) => id.name == "__dirname" || id.name == "__filename",
        Expression::BinaryExpression(be) => {
            matches!(be.operator, BinaryOperator::Addition)
                && is_static_path(&be.left)
                && is_static_path(&be.right)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check_js(code: &str) -> Vec<Violation> {
        check(code, "/src/app.ts")
    }

    // --- err-stack-exposure ---

    #[test]
    fn t001_res_json_with_stack() {
        let v = check_js("res.json({ stack: err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn t002_res_status_json_with_stack() {
        let v = check_js("res.status(500).json({ stack: error.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn t003_logger_with_stack_safe() {
        assert!(check_js("logger.error({ stack: err.stack });").is_empty());
    }

    #[test]
    fn t004_console_with_stack_safe() {
        assert!(check_js("console.error(err.stack);").is_empty());
    }

    #[test]
    fn t005_res_json_no_stack() {
        assert!(check_js("res.json({ error: err.message });").is_empty());
    }

    #[test]
    fn res_send_with_stack() {
        let v = check_js("res.send({ stack: err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn response_json_with_stack() {
        let v = check_js("response.json({ stack: err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn response_status_json_with_stack() {
        let v = check_js("response.status(500).json({ error: err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn nested_stack_in_object() {
        let v = check_js("res.json({ data: { detail: err.stack } });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_conditional() {
        let v = check_js("res.json({ error: isDev ? err.stack : 'error' });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_logical() {
        let v = check_js("res.json({ error: err && err.stack });");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    #[test]
    fn stack_in_array() {
        let v = check_js("res.json([err.stack]);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    // --- child-process-injection ---

    #[test]
    fn t006_exec_variable() {
        let v = check_js("exec(userInput);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn t007_exec_sync_variable() {
        let v = check_js("execSync(cmd);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn t008_spawn_variable() {
        let v = check_js("spawn(variable, args);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::High);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn t009_exec_literal_safe() {
        assert!(check_js("exec('ls -la');").is_empty());
    }

    #[test]
    fn t010_exec_template_literal_blocked() {
        let v = check_js("exec(`ls ${dir}`);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn spawn_sync_variable() {
        let v = check_js("spawnSync(cmd, args);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn exec_static_template_safe() {
        assert!(check_js("exec(`ls -la`);").is_empty());
    }

    #[test]
    fn t011_exec_file_literal_safe() {
        assert!(check_js("execFile('/usr/bin/git', args);").is_empty());
    }

    // --- non-literal-fs-path ---

    #[test]
    fn t012_fs_read_variable() {
        let v = check_js("fs.readFile(userInput, cb);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].severity, Severity::Medium);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn t013_fs_write_sync_variable() {
        let v = check_js("fs.writeFileSync(variable, data);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn t014_fs_read_literal_safe() {
        assert!(check_js("fs.readFile('./config.json', cb);").is_empty());
    }

    #[test]
    fn t015_fs_read_dirname_concat_safe() {
        assert!(check_js("fs.readFile(__dirname + '/file', cb);").is_empty());
    }

    #[test]
    fn fs_read_filename_safe() {
        assert!(check_js("fs.readFile(__filename, cb);").is_empty());
    }

    #[test]
    fn fs_read_chained_concat_safe() {
        assert!(check_js("fs.readFile(__dirname + '/sub' + '/file', cb);").is_empty());
    }

    #[test]
    fn fs_read_static_template_safe() {
        assert!(check_js("fs.readFile(`./config.json`, cb);").is_empty());
    }

    #[test]
    fn t016_fs_read_path_join_variable() {
        let v = check_js("fs.readFileSync(path.join(__dirname, f));");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    // --- fail-open / edge cases ---

    #[test]
    fn t017_invalid_syntax_fail_open() {
        assert!(check_js("function { invalid syntax !!!").is_empty());
    }

    #[test]
    fn t018_empty_file() {
        assert!(check_js("").is_empty());
    }

    #[test]
    fn t019_css_file_skipped() {
        assert!(check("body { color: red; }", "/src/styles.css").is_empty());
    }

    #[test]
    fn nfr001_performance_under_10ms() {
        let content = r#"
import { exec, execSync } from 'child_process';
import * as fs from 'fs';

export async function handler(req, res) {
    try {
        const data = fs.readFileSync('./config.json', 'utf-8');
        const result = await processData(data);
        exec('echo done', (err) => { if (err) console.error(err); });
        res.json({ success: true, data: result });
    } catch (err) {
        logger.error({ stack: err.stack, message: err.message });
        res.status(500).json({ error: 'Internal Server Error' });
    }
}

function runScript(script) {
    return execSync(script);
}

function loadFile(filePath) {
    return fs.readFile(filePath, 'utf-8', (err, data) => data);
}
"#;
        let start = std::time::Instant::now();
        let iterations = 100;
        for _ in 0..iterations {
            let _ = check(content, "/src/api/handler.ts");
        }
        let elapsed = start.elapsed();
        let per_file_us = elapsed.as_micros() / iterations;
        eprintln!("NFR-001: {per_file_us}µs/file ({iterations} iterations)");
        assert!(
            per_file_us < 10_000,
            "AST check exceeded 10ms/file: {per_file_us}µs"
        );
    }

    // --- ComputedMemberExpression ---

    #[test]
    fn computed_member_exec_blocked() {
        let v = check_js(r#"cp["exec"](userInput);"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::CHILD_PROCESS_INJECTION);
    }

    #[test]
    fn computed_member_exec_literal_safe() {
        assert!(check_js(r#"cp["exec"]("ls -la");"#).is_empty());
    }

    #[test]
    fn computed_member_fs_blocked() {
        let v = check_js(r#"fs["readFile"](userInput, cb);"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn computed_member_res_json_stack() {
        let v = check_js(r#"res["json"]({ stack: err.stack });"#);
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    // --- Boundary conditions ---

    #[test]
    fn fs_dirname_plus_variable_blocked() {
        let v = check_js("fs.readFile(__dirname + userInput, cb);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn fs_unlink_variable_blocked() {
        let v = check_js("fs.unlink(variable, cb);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::NON_LITERAL_FS_PATH);
    }

    #[test]
    fn stack_in_template_literal() {
        let v = check_js("res.json(`error: ${err.stack}`);");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].rule, rule_id::ERR_STACK_EXPOSURE);
    }

    // --- Known limitations ---

    #[test]
    fn known_limitation_spread_err_not_detected() {
        assert!(check_js("res.json({ ...err });").is_empty());
    }

    #[test]
    fn known_limitation_aliased_fs_not_detected() {
        assert!(check_js("fileSystem.readFile(userInput, cb);").is_empty());
    }

    #[test]
    fn known_limitation_require_fs_not_detected() {
        assert!(check_js("require('fs').readFile(userInput, cb);").is_empty());
    }
}
