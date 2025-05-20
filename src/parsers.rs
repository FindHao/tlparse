use crate::templates::TEMPLATE_QUERY_PARAM_SCRIPT;
use crate::{types::*, ParseConfig};
use html_escape::encode_text;
use once_cell::sync::Lazy;
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use tinytemplate::TinyTemplate;

use serde_json::Value;

use syntect::highlighting::ThemeSet;
use syntect::parsing::SyntaxSet;

pub enum ParserOutput {
    File(PathBuf, String),       // File to be saved on disk
    GlobalFile(PathBuf, String), // Like file, but don't give a unique suffix
    Link(String, String), // External href to (name, url) (linked in compile_directory, not returned)
}

// Each parser returns a list of files to save and links to render in compile directory
pub type ParserResults = Vec<ParserOutput>;

/**
 * StructuredLogParser
 * Parses a structured log and returns a vec of file outputs.
 * Implement this trait to add your own analyses.
 *
 * 'e is the lifetime of the envelope being parsed
 */
pub trait StructuredLogParser {
    // If this returns Some value, the parser will be run on that metadata.
    // Otherwise, it will be skipped.
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>>;

    // Take a log input and the metadata you asked for, return a set of files to write
    fn parse<'e>(
        &self,
        lineno: usize,                  // Line number from log
        metadata: Metadata<'e>,         // Metadata from get_metadata
        rank: Option<u32>,              // Rank of the log
        compile_id: &Option<CompileId>, // Compile ID of the envelope
        payload: &str,                  // Payload from the log (empty string when None)
    ) -> anyhow::Result<ParserResults>;

    // Name of the parser, for error logging
    fn name(&self) -> &'static str;
}

// Takes a filename and a payload and writes that payload into a the file
fn simple_file_output(
    filename: &str,
    lineno: usize,
    compile_id: &Option<CompileId>,
    payload: &str,
) -> anyhow::Result<ParserResults> {
    let compile_id_dir: PathBuf = compile_id
        .as_ref()
        .map_or(format!("unknown_{lineno}"), |cid| cid.as_directory_name())
        .into();
    let subdir = PathBuf::from(compile_id_dir);
    let f = subdir.join(filename);
    Ok(Vec::from([ParserOutput::File(f, String::from(payload))]))
}

/**
 * Parser for simple output dumps where the metadata is a sentinel {}
 */
pub struct SentinelFileParser {
    filename: &'static str,
    get_sentinel: fn(&Envelope) -> Option<&EmptyMetadata>,
}
impl SentinelFileParser {
    pub fn new(
        filename: &'static str,
        get_sentinel: fn(&Envelope) -> Option<&EmptyMetadata>,
    ) -> Self {
        Self {
            filename,
            get_sentinel,
        }
    }
}
impl StructuredLogParser for SentinelFileParser {
    fn name(&self) -> &'static str {
        self.filename
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        (self.get_sentinel)(e).map(|m| Metadata::Empty(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        _metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        simple_file_output(
            &format!("{}.txt", self.filename),
            lineno,
            compile_id,
            payload,
        )
    }
}

/**
 * Generic parser for graph_dump entries
 */
pub struct GraphDumpParser;
impl StructuredLogParser for GraphDumpParser {
    fn name(&self) -> &'static str {
        "graph_dump" // ToDO: more specific?
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.graph_dump.as_ref().map(|m| Metadata::GraphDump(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::GraphDump(metadata) = metadata {
            let filename: PathBuf = {
                let mut r = OsString::from(&metadata.name);
                r.push(OsStr::new(".txt"));
                r.into()
            };
            simple_file_output(&filename.to_string_lossy(), lineno, compile_id, payload)
        } else {
            Err(anyhow::anyhow!("Expected GraphDump metadata"))
        }
    }
}

// Same as SentinelFileParser, but can log the size of the graph
pub struct DynamoOutputGraphParser;
impl StructuredLogParser for DynamoOutputGraphParser {
    fn name(&self) -> &'static str {
        "dynamo_output_graph"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.dynamo_output_graph
            .as_ref()
            .map(|m| Metadata::DynamoOutputGraph(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        _metadata: Metadata<'e>, // TODO: log size of graph
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        simple_file_output("dynamo_output_graph.txt", lineno, compile_id, payload)
    }
}

pub struct DynamoGuardParser<'t> {
    tt: &'t TinyTemplate<'t>,
}
impl StructuredLogParser for DynamoGuardParser<'_> {
    fn name(&self) -> &'static str {
        "dynamo_guards"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.dynamo_guards.as_ref().map(|m| Metadata::Empty(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        _metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        let filename = format!("{}.html", self.name());
        let guards = serde_json::from_str::<Vec<DynamoGuard>>(payload)?;
        let guards_context = DynamoGuardsContext {
            guards,
            qps: TEMPLATE_QUERY_PARAM_SCRIPT,
        };
        let output = self.tt.render(&filename, &guards_context)?;
        simple_file_output(&filename, lineno, compile_id, &output)
    }
}

pub struct InductorOutputCodeParser {
    // If true we output the code as plain text, otherwise we output it as rendered html
    plain_text: bool,
}

impl InductorOutputCodeParser {
    pub fn new(config: &ParseConfig) -> Self {
        InductorOutputCodeParser {
            plain_text: config.plain_text,
        }
    }
}

impl StructuredLogParser for InductorOutputCodeParser {
    fn name(&self) -> &'static str {
        "inductor_output_code"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.inductor_output_code
            .as_ref()
            .map(|m| Metadata::InductorOutputCode(m))
    }

    fn parse<'e>(
        &self,
        lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::InductorOutputCode(metadata) = metadata {
            let filename = metadata
                .filename
                .as_ref()
                .and_then(|p| Path::file_stem(p))
                .map_or_else(
                    || {
                        if self.plain_text {
                            PathBuf::from("inductor_output_code.txt")
                        } else {
                            PathBuf::from("inductor_output_code.html")
                        }
                    },
                    |stem| {
                        let mut r = OsString::from("inductor_output_code_");
                        r.push(stem);
                        if self.plain_text {
                            r.push(OsStr::new(".txt"));
                        } else {
                            r.push(OsStr::new(".html"));
                        }
                        r.into()
                    },
                );
            let output_content = if self.plain_text {
                payload.to_string()
            } else {
                match generate_html_output(payload) {
                    Ok(html) => html,
                    Err(_e) => {
                        return Err(anyhow::anyhow!("Failed to parse inductor code to html"))
                    }
                }
            };

            simple_file_output(
                &filename.to_string_lossy(),
                lineno,
                compile_id,
                &output_content,
            )
        } else {
            Err(anyhow::anyhow!("Expected InductorOutputCode metadata"))
        }
    }
}

fn generate_html_output(payload: &str) -> Result<String, anyhow::Error> {
    let syntax_set = SyntaxSet::load_defaults_newlines();
    let theme_set = ThemeSet::load_defaults();
    let syntax = syntax_set.find_syntax_by_extension("py").unwrap();
    let html = syntect::html::highlighted_html_for_string(
        &payload,
        &syntax_set,
        &syntax,
        &theme_set.themes["InspiredGitHub"],
    );
    Ok(html?)
}

pub struct OptimizeDdpSplitChildParser;
impl StructuredLogParser for OptimizeDdpSplitChildParser {
    fn name(&self) -> &'static str {
        "optimize_ddp_split_child"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.optimize_ddp_split_child
            .as_ref()
            .map(|m| Metadata::OptimizeDdpSplitChild(m))
    }

    fn parse<'e>(
        &self,
        lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::OptimizeDdpSplitChild(m) = metadata {
            let filename = format!("optimize_ddp_split_child_{}.txt", m.name);
            simple_file_output(&filename, lineno, compile_id, payload)
        } else {
            Err(anyhow::anyhow!("Expected OptimizeDdpSplitChild metadata"))
        }
    }
}

pub struct LinkParser;
impl StructuredLogParser for LinkParser {
    fn name(&self) -> &'static str {
        "link_parser"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.link.as_ref().map(|m| Metadata::Link(m))
    }

    fn parse<'e>(
        &self,
        _lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        _compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::Link(m) = metadata {
            Ok(Vec::from([ParserOutput::Link(
                m.name.clone(),
                m.url.clone(),
            )]))
        } else {
            Err(anyhow::anyhow!("Expected Link Metadata"))
        }
    }
}

fn format_stack(stack: &StackSummary, caption: &str, open: bool) -> String {
    let mut trie = StackTrieNode::default();
    trie.insert_no_terminal(stack.to_vec());
    trie.fmt(None, caption, open).unwrap()
}

pub struct CompilationMetricsParser<'t> {
    pub tt: &'t TinyTemplate<'t>,
    pub stack_index: &'t RefCell<StackIndex>,
    pub symbolic_shape_specialization_index: &'t RefCell<SymbolicShapeSpecializationIndex>,
    pub guard_added_fast_index: &'t RefCell<GuardAddedFastIndex>,
    pub output_files: &'t Vec<OutputFile>,
    pub compile_id_dir: &'t PathBuf,
}
impl StructuredLogParser for CompilationMetricsParser<'_> {
    fn name(&self) -> &'static str {
        "compilation_metrics"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.compilation_metrics
            .as_ref()
            .map(|m| Metadata::CompilationMetrics(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metrics: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        let filename = format!("{}.html", self.name());
        if let Metadata::CompilationMetrics(m) = metrics {
            let id = compile_id
                .clone()
                .map_or("(unknown) ".to_string(), |c| format!("{cid} ", cid = c));
            let mut cid = compile_id.clone();
            if let Some(c) = cid.as_mut() {
                if let Some(_frame_id) = c.frame_compile_id {
                    // data migration for old logs that don't have attempt
                    c.attempt = Some(0);
                }
            }
            let stack_html = self
                .stack_index
                .borrow()
                .get(&cid)
                .map_or("".to_string(), |stack| format_stack(stack, "Stack", false));
            let mini_stack_html = if let (Some(name), Some(filename), Some(line)) =
                (&m.co_name, &m.co_filename, m.co_firstlineno)
            {
                format_stack(
                    &Vec::from([FrameSummary {
                        uninterned_filename: Some(filename.clone()),
                        filename: u32::MAX,
                        line: line,
                        name: name.clone(),
                        loc: None,
                    }]),
                    "Stack",
                    false,
                )
            } else {
                "".to_string()
            };
            let specializations = self
                .symbolic_shape_specialization_index
                .borrow_mut()
                .remove(&cid)
                .unwrap_or(Vec::new())
                .drain(..)
                .map(|spec| SymbolicShapeSpecializationContext {
                    symbol: spec.symbol.unwrap_or("".to_string()),
                    sources: spec.sources.unwrap_or(Vec::new()),
                    value: spec.value.unwrap_or("".to_string()),
                    user_stack_html: format_stack(
                        &spec.user_stack.unwrap_or(Vec::new()),
                        "User Stack",
                        false,
                    ),
                    stack_html: format_stack(
                        &spec.stack.unwrap_or(Vec::new()),
                        "Framework Stack",
                        false,
                    ),
                })
                .collect();
            let guards_added_fast = self
                .guard_added_fast_index
                .borrow_mut()
                .remove(&cid)
                .unwrap_or(Vec::new())
                .drain(..)
                .map(|guard| GuardAddedFastContext {
                    expr: guard.expr.unwrap_or("".to_string()),
                    user_stack_html: format_stack(
                        &guard.user_stack.unwrap_or(Vec::new()),
                        "User Stack",
                        false,
                    ),
                    stack_html: format_stack(
                        &guard.stack.unwrap_or(Vec::new()),
                        "Framework Stack",
                        false,
                    ),
                })
                .collect();
            let remove_prefix = |x: &String| -> String {
                // url is X_Y_Z/<rest>. Get the rest of the string for the link
                // on compilation metrics page
                let parts: Vec<_> = x.split("/").collect();
                let new_str: String = parts[1..].join("");
                new_str
            };
            let output_files: Vec<OutputFile> = self
                .output_files
                .iter()
                .map(|o| OutputFile {
                    url: remove_prefix(&o.url),
                    name: remove_prefix(&o.name),
                    number: o.number.clone(),
                    suffix: o.suffix.clone(),
                })
                .collect();
            let context = CompilationMetricsContext {
                css: crate::CSS,
                m: &m,
                compile_id: id,
                stack_html: stack_html,
                mini_stack_html: mini_stack_html,
                symbolic_shape_specializations: specializations,
                guards_added_fast: guards_added_fast,
                output_files: &output_files,
                compile_id_dir: &self.compile_id_dir,
                qps: TEMPLATE_QUERY_PARAM_SCRIPT,
            };
            let output = self.tt.render(&filename, &context)?;
            simple_file_output(&filename, lineno, compile_id, &output)
        } else {
            Err(anyhow::anyhow!("Expected CompilationMetrics metadata"))
        }
    }
}

pub struct AOTAutogradBackwardCompilationMetricsParser<'t> {
    tt: &'t TinyTemplate<'t>,
}
impl StructuredLogParser for AOTAutogradBackwardCompilationMetricsParser<'_> {
    fn name(&self) -> &'static str {
        "aot_autograd_backward_compilation_metrics"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.aot_autograd_backward_compilation_metrics
            .as_ref()
            .map(|m| Metadata::AOTAutogradBackwardCompilationMetrics(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metrics: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        let filename = format!("{}.html", self.name());
        if let Metadata::AOTAutogradBackwardCompilationMetrics(m) = metrics {
            let id = compile_id
                .clone()
                .map_or("(unknown) ".to_string(), |c| format!("{cid} ", cid = c));
            let context = AOTAutogradBackwardCompilationMetricsContext {
                css: crate::CSS,
                m: &m,
                compile_id: id,
                qps: TEMPLATE_QUERY_PARAM_SCRIPT,
            };
            let output = self.tt.render(&filename, &context)?;
            simple_file_output(&filename, lineno, compile_id, &output)
        } else {
            Err(anyhow::anyhow!(
                "Expected AOTAutogradBackwardCompilationMetrics metadata"
            ))
        }
    }
}

pub struct BwdCompilationMetricsParser<'t> {
    tt: &'t TinyTemplate<'t>,
}
impl StructuredLogParser for BwdCompilationMetricsParser<'_> {
    fn name(&self) -> &'static str {
        "bwd_compilation_metrics"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.bwd_compilation_metrics
            .as_ref()
            .map(|m| Metadata::BwdCompilationMetrics(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metrics: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        let filename = format!("{}.html", self.name());
        if let Metadata::BwdCompilationMetrics(m) = metrics {
            let id = compile_id
                .clone()
                .map_or("(unknown) ".to_string(), |c| format!("{cid} ", cid = c));
            let context = BwdCompilationMetricsContext {
                css: crate::CSS,
                m: &m,
                compile_id: id,
                qps: TEMPLATE_QUERY_PARAM_SCRIPT,
            };
            let output = self.tt.render(&filename, &context)?;
            simple_file_output(&filename, lineno, compile_id, &output)
        } else {
            Err(anyhow::anyhow!("Expected BwdCompilationMetrics metadata"))
        }
    }
}

pub struct DumpFileParser;
impl StructuredLogParser for DumpFileParser {
    fn name(&self) -> &'static str {
        "dump_file"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.dump_file.as_ref().map(|m| Metadata::DumpFile(m))
    }
    fn parse<'e>(
        &self,
        _lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        _compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::DumpFile(metadata) = metadata {
            let mb_fx_id = extract_eval_with_key_id(&metadata.name);
            let filename = if let Some(fx_id) = mb_fx_id {
                format!("eval_with_key_{}.html", fx_id)
            } else {
                format!("{}.html", metadata.name)
            };
            let subdir = PathBuf::from("dump_file");
            let f = subdir.join(filename);
            Ok(Vec::from([ParserOutput::GlobalFile(
                f,
                anchor_source(payload),
            )]))
        } else {
            Err(anyhow::anyhow!("Expected DumpFile metadata"))
        }
    }
}

pub fn anchor_source(text: &str) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut html = String::from(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Source Code</title>
    <style>
        pre {
            counter-reset: line;
        }
        pre span {
            display: block;
        }
        pre span:before {
            counter-increment: line;
            content: counter(line);
            display: inline-block;
            padding: 0 .5em;
            margin-right: .5em;
            color: #888;
        }
        pre span:target {
            background-color: #ffff00;
        }
    </style>
</head>
<body>
    <pre>"#,
    );

    for (i, line) in lines.iter().enumerate() {
        let line_number = i + 1;
        html.push_str(&format!(
            r#"<span id="L{}">{}</span>"#,
            line_number,
            encode_text(line)
        ));
    }

    html.push_str(&format!(
        "</pre>{TEMPLATE_QUERY_PARAM_SCRIPT}</body></html>"
    ));
    html
}

pub struct ArtifactParser;
impl StructuredLogParser for ArtifactParser {
    fn name(&self) -> &'static str {
        "artifact"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        e.artifact.as_ref().map(|m| Metadata::Artifact(m))
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::Artifact(metadata) = metadata {
            match metadata.encoding.as_str() {
                "string" => {
                    let filename = format!("{}.txt", metadata.name);
                    simple_file_output(&filename, lineno, compile_id, &payload)
                }
                "json" => {
                    let filename = format!("{}.json", metadata.name);
                    let value: Value = serde_json::from_str(&payload).unwrap();
                    let pretty = serde_json::to_string_pretty(&value).unwrap();
                    simple_file_output(&filename, lineno, compile_id, &pretty)
                }
                _ => Err(anyhow::anyhow!(
                    "Unsupported encoding: {}",
                    metadata.encoding
                )),
            }
        } else {
            Err(anyhow::anyhow!("Expected Artifact metadata"))
        }
    }
}

fn render_sym_expr_trie(
    expr: u64,
    sym_expr_info_index: &SymExprInfoIndex,
    depth: usize,
    visited: &mut HashSet<u64>,
) -> Option<String> {
    if visited.contains(&expr) {
        return None;
    }
    visited.insert(expr);

    let sym_expr_info = sym_expr_info_index.get(&expr)?;
    let binding = Vec::new();
    let sym_expr_args_id = sym_expr_info.argument_ids.as_ref().unwrap_or(&binding);

    let mut children_elements = Vec::new();
    for arg_id in sym_expr_args_id {
        if let Some(child_element) =
            render_sym_expr_trie(*arg_id, sym_expr_info_index, depth + 1, visited)
        {
            children_elements.push(child_element);
        }
    }

    let mut sym_expr_trie_html = format!(
        r#"
<div style="margin-left: {}px;">
    <div style="padding: 16px; border: 1px solid #ccc; border-radius: 8px; box-shadow: 2px 2px 5px rgba(0,0,0,0.1); background-color: white;">
        <h3 style="font-weight: bold; font-size: 1.25rem;">{}</h3>
        <div style="margin-top: 8px;">
            <p><span style="font-weight: bold;">Method:</span> {}</p>
            <p><span style="font-weight: bold;">Arguments:</span> {}</p>
            <div style="margin-top: 8px; font-size: 0.875rem;">
            {}
            {}
            </div>
        </div>
    </div>
</div>
"#,
        depth * 20,
        sym_expr_info.result.as_ref().unwrap_or(&"".to_string()),
        sym_expr_info.method.as_ref().unwrap_or(&"".to_string()),
        sym_expr_info
            .arguments
            .as_ref()
            .unwrap_or(&Vec::new())
            .join(", "),
        format_stack(
            &sym_expr_info.user_stack.as_ref().unwrap_or(&Vec::new()),
            "User Stack",
            true
        ),
        format_stack(
            &sym_expr_info.stack.as_ref().unwrap_or(&Vec::new()),
            "Stack",
            false
        ),
    );
    if !children_elements.is_empty() {
        for child_element in children_elements {
            sym_expr_trie_html.push_str(&child_element);
        }
    }
    Some(sym_expr_trie_html)
}

pub struct PropagateRealTensorsParser<'t> {
    pub tt: &'t TinyTemplate<'t>,
    pub sym_expr_info_index: &'t SymExprInfoIndex,
}
impl StructuredLogParser for PropagateRealTensorsParser<'_> {
    fn name(&self) -> &'static str {
        "guard_added"
    }
    fn get_metadata<'e>(&self, e: &'e Envelope) -> Option<Metadata<'e>> {
        if let Some(m) = e.propagate_real_tensors_provenance.as_ref() {
            return Some(Metadata::SymbolicShapePropagateRealTensor(m));
        }
        if let Some(g) = e.guard_added.as_ref() {
            return Some(Metadata::SymbolicShapePropagateRealTensor(g));
        }
        return None;
    }
    fn parse<'e>(
        &self,
        lineno: usize,
        metadata: Metadata<'e>,
        _rank: Option<u32>,
        compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        if let Metadata::SymbolicShapePropagateRealTensor(m) = metadata {
            let filename = "symbolic_guard_information.html";
            let framework_stack_html = format_stack(
                &m.stack.as_ref().unwrap_or(&Vec::new()),
                "Framework Stack",
                false,
            );
            let user_stack_html = format_stack(
                &m.user_stack.as_ref().unwrap_or(&Vec::new()),
                "User Stack",
                true,
            );
            let locals_html = format!(
                "{}",
                m.frame_locals.as_ref().unwrap_or(&FrameLocals::default())
            );

            let mut visited = HashSet::new();
            let sym_expr_trie_html = render_sym_expr_trie(
                m.expr_node_id.unwrap(),
                self.sym_expr_info_index,
                0,
                &mut visited,
            )
            .unwrap_or("".to_string());

            let context = SymbolicGuardContext {
                css: crate::CSS,
                expr: m.expr.clone().unwrap(),
                user_stack_html: user_stack_html,
                framework_stack_html: framework_stack_html,
                sym_expr_trie_html: sym_expr_trie_html,
                locals_html: locals_html,
            };
            let output = self.tt.render(&filename, &context)?;
            simple_file_output(&filename, lineno, compile_id, &output)
        } else {
            Err(anyhow::anyhow!(
                "Expected SymbolicShapePropagateRealTensor metadata"
            ))
        }
    }
}

pub struct TritonParseParser {
    // JSON config file containing tritonparse_url_prefix and file paths
    pub tritonparse_config_path: PathBuf,
    // URL prefix will be loaded from the config file
    pub tritonparse_url_prefix: String,
    // Maps ranks to their respective files
    // rank_files[None] contains the default files for unspecified ranks
    // rank_files[Some(rank)] contains the files for the specific rank
    pub rank_files: HashMap<Option<u32>, RankFiles>,
}

// Files for a specific rank
pub struct RankFiles {
    pub regular_files: Vec<String>,
    // Each rank will have at most one mapped file
    pub mapped_file: Option<String>,
}

impl TritonParseParser {
    pub fn new(tritonparse_config_path: PathBuf) -> Self {
        // Initialize with empty values that will be populated when we read the config file
        let mut parser = Self {
            tritonparse_config_path,
            tritonparse_url_prefix: String::new(),
            rank_files: HashMap::new(),
        };
        
        // Read and parse the config file
        if let Ok(config_data) = std::fs::read_to_string(&parser.tritonparse_config_path) {
            if let Ok(config) = serde_json::from_str::<serde_json::Value>(&config_data) {
                // Extract tritonparse_url_prefix
                if let Some(url_prefix) = config.get("tritonparse_url_prefix").and_then(|v| v.as_str()) {
                    parser.tritonparse_url_prefix = url_prefix.to_string();
                } else {
                    println!("Warning: tritonparse_url_prefix not found in config file");
                }
                
                // Process each key in the config
                for (key, value) in config.as_object().unwrap_or(&serde_json::Map::new()) {
                    // Skip the url_prefix key as it's already processed
                    if key == "tritonparse_url_prefix" {
                        continue;
                    }
                    
                    // Parse the rank from the key
                    let rank = if key == "rank_default" {
                        None
                    } else if key.starts_with("rank_") {
                        match key[5..].parse::<u32>() {
                            Ok(r) => Some(r),
                            Err(_) => {
                                println!("Warning: Invalid rank format: {}", key);
                                continue;
                            }
                        }
                    } else {
                        // Skip keys that don't follow our rank format
                        continue;
                    };
                    
                    // Extract regular files
                    let regular_files = if let Some(files) = value.get("regular_files").and_then(|v| v.as_array()) {
                        files
                            .iter()
                            .filter_map(|v| v.as_str().map(|s| s.to_string()))
                            .collect()
                    } else {
                        Vec::new()
                    };
                    
                    // Extract mapped file (only one per rank)
                    let mapped_file = if let Some(files) = value.get("mapped_files").and_then(|v| v.as_array()) {
                        if let Some(first) = files.first().and_then(|v| v.as_str()) {
                            if files.len() > 1 {
                                println!("Warning: Multiple mapped files specified for rank {}, using only the first one", 
                                         rank.map_or("default".to_string(), |r| r.to_string()));
                            }
                            Some(first.to_string())
                        } else {
                            None
                        }
                    } else {
                        None
                    };
                    
                    // Add to rank_files
                    parser.rank_files.insert(rank, RankFiles { 
                        regular_files, 
                        mapped_file
                    });
                }
                
                // If there's no default rank entry, create an empty one
                if !parser.rank_files.contains_key(&None) {
                    parser.rank_files.insert(None, RankFiles {
                        regular_files: Vec::new(),
                        mapped_file: None,
                    });
                }
            } else {
                println!("Error: Failed to parse tritonparse config JSON");
            }
        } else {
            println!("Error: Failed to read tritonparse config file");
        }
        
        parser
    }
    
    fn get_files_for_rank(&self, rank: Option<u32>) -> &RankFiles {
        // Try to get files for the specific rank
        if let Some(files) = self.rank_files.get(&rank) {
            return files;
        }
        
        // Try to fall back to default rank
        if let Some(files) = self.rank_files.get(&None) {
            return files;
        }
        
        // If both specific rank and default rank don't exist, return empty files from a static reference
        // This avoids the lifetime issues with thread_local
        
        // Create a static empty RankFiles reference
        static EMPTY_RANK_FILES: Lazy<RankFiles> = Lazy::new(|| {
            RankFiles {
                regular_files: Vec::new(),
                mapped_file: None,
            }
        });
        
        &EMPTY_RANK_FILES
    }
}

impl StructuredLogParser for TritonParseParser {
    fn name(&self) -> &'static str {
        "tritonparse"
    }

    fn get_metadata<'e>(&self, _e: &'e Envelope) -> Option<Metadata<'e>> {
        // Always return metadata so the parse method will be called once
        Some(Metadata::Empty(&EmptyMetadata {}))
    }

    fn parse<'e>(
        &self,
        _lineno: usize,
        _metadata: Metadata<'e>,
        rank: Option<u32>,
        compile_id: &Option<CompileId>,
        _payload: &str,
    ) -> anyhow::Result<ParserResults> {
        // Debug print for rank using pattern matching
        if let Some(rank_value) = rank {
            println!("TritonParseParser processing for rank: {}", rank_value);
        } else {
            println!("Note: TritonParseParser using default rank");
        }
        
        // Distinguish two cases:
        // 1. When processing log entries with CompileId, only look for corresponding regular tritonparse files
        // 2. When processing log entries without CompileId, only look for mapped files
        use std::sync::Mutex;
        
        // Get files for the current rank
        let rank_files = self.get_files_for_rank(rank);
        
        // Track already processed compile_ids
        thread_local! {
            static PROCESSED_ONCE: Mutex<HashSet<String>> = Mutex::new(HashSet::new());
        }
        
        let mut results = Vec::new();
        
        if let Some(cid) = compile_id {
            // Check if this compilation ID has already been processed
            let cid_str = cid.to_string();
            let mut should_process = true;
            
            PROCESSED_ONCE.with(|processed| {
                let mut processed = processed.lock().unwrap();
                if processed.contains(&cid_str) {
                    should_process = false;
                } else {
                    processed.insert(cid_str.clone());
                }
            });
            
            if !should_process {
                return Ok(Vec::new());
            }
            
            // Check if cid_str contains "[-/-]"
            if cid_str.contains("[-/-]") || (cid.frame_id.is_none() && cid.frame_compile_id.is_none()) {
                // Invalid CompileId value - look for mapped files, placed under [-/-]
                // Use static atomic boolean to ensure the mapped file is processed only once
                static MAPPED_FILE_PROCESSED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
                
                if !MAPPED_FILE_PROCESSED.swap(true, std::sync::atomic::Ordering::SeqCst) {
                    // Process mapped file from the config file for this rank
                    if let Some(file_name) = &rank_files.mapped_file {
                        // Generate complete URL
                        let url = format!("{}{}", self.tritonparse_url_prefix, file_name);
                        
                        // Add link - this will appear in the [-/-] directory
                        results.push(ParserOutput::Link(
                            format!("TritonParse: {}", file_name),
                            url,
                        ));
                    }
                }
            } else {
                // Valid CompileId value - look for regular files
                
                // Build regular tritonparse filename pattern to match against
                let filename_pattern = format!(
                    "f{}_fc{}_a{}_cai{}",
                    cid.frame_id.unwrap_or(0),
                    cid.frame_compile_id.unwrap_or(0),
                    cid.attempt.unwrap_or(0),
                    cid.compiled_autograd_id.map_or("-".to_string(), |v| v.to_string())
                );
                
                // Look for matching files in the regular_files list for this rank
                for file_name in &rank_files.regular_files {
                    if file_name.contains(&filename_pattern) {
                        // Generate complete URL
                        let url = format!("{}{}", self.tritonparse_url_prefix, file_name);
                        
                        // Add link - this will appear in the normal directory
                        results.push(ParserOutput::Link(
                            format!("TritonParse: {}", file_name),
                            url,
                        ));
                    }
                }
            }
        } else {
            // Print debug info when CompileId is null
            println!("Warning: TritonParseParser received a null CompileId, this should not happen.");
        }
        
        Ok(results)
    }
}

// Register your parser here
pub fn default_parsers<'t>(
    tt: &'t TinyTemplate<'t>,
    parser_config: &ParseConfig,
) -> Vec<Box<dyn StructuredLogParser + 't>> {
    // We need to use Box wrappers here because vecs in Rust need to have known size
    if parser_config.export {
        return vec![Box::new(SentinelFileParser::new("exported_program", |e| {
            e.exported_program.as_ref()
        }))];
    }

    let result: Vec<Box<dyn StructuredLogParser>> = vec![
        Box::new(SentinelFileParser::new("optimize_ddp_split_graph", |e| {
            e.optimize_ddp_split_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("compiled_autograd_graph", |e| {
            e.compiled_autograd_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("aot_forward_graph", |e| {
            e.aot_forward_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("aot_backward_graph", |e| {
            e.aot_backward_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("aot_inference_graph", |e| {
            e.aot_inference_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("aot_joint_graph", |e| {
            e.aot_joint_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("inductor_post_grad_graph", |e| {
            e.inductor_post_grad_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("inductor_pre_grad_graph", |e| {
            e.inductor_pre_grad_graph.as_ref()
        })),
        Box::new(SentinelFileParser::new("dynamo_cpp_guards_str", |e| {
            e.dynamo_cpp_guards_str.as_ref()
        })),
        Box::new(GraphDumpParser),
        Box::new(DynamoOutputGraphParser),
        Box::new(DynamoGuardParser { tt }),
        Box::new(InductorOutputCodeParser::new(parser_config)),
        Box::new(OptimizeDdpSplitChildParser),
        Box::new(AOTAutogradBackwardCompilationMetricsParser { tt }), // TODO: use own tt instances
        Box::new(BwdCompilationMetricsParser { tt }),                 // TODO: use own tt instances
        Box::new(LinkParser),
        Box::new(ArtifactParser),
        Box::new(DumpFileParser),
    ];

    result
}
