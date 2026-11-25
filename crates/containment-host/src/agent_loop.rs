//! The owned agent harness (design spec section 7, Path A). It runs inside the
//! sandbox as the agent and is untrusted like any agent: every claim is checked
//! outside it. Its only way out is the gateway socket: `infer` for the model,
//! `http` for the network, `log` for its own narration. Files live in
//! /workspace, which is discarded when the sandbox is rebuilt.
use serde_json::{json, Value};
use std::error::Error;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Component, Path, PathBuf};
use std::time::Duration;

const WORKSPACE: &str = "/workspace";
const MAX_TOOL_OUTPUT: usize = 6_000;

struct Gateway {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Gateway {
    fn connect(path: &str) -> std::io::Result<Self> {
        let stream = UnixStream::connect(path)?;
        // Longer than any model call the policy can allow; the gateway answers or closes first.
        stream.set_read_timeout(Some(Duration::from_secs(crate::live::MAX_MODEL_TIMEOUT_SECONDS + 60)))?;
        Ok(Self { reader: BufReader::new(stream.try_clone()?), stream })
    }

    fn send(&mut self, message: &Value) -> Value {
        if writeln!(self.stream, "{message}").is_err() {
            return json!({"ok": false, "error": "closed"});
        }
        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(n) if n > 0 => serde_json::from_str(&line).unwrap_or_else(|_| json!({"ok": false, "error": "bad reply"})),
            _ => json!({"ok": false, "error": "closed"}),
        }
    }
}

fn say(event: &str, value: Value) {
    println!("{}", json!({"event": event, "value": value}));
    let _ = std::io::stdout().flush();
}

fn clip(text: &str, limit: usize) -> String {
    if text.len() <= limit {
        return text.to_owned();
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}… [{} more bytes]", &text[..end], text.len() - end)
}

/// Resolves a path inside /workspace. `..` and absolute paths elsewhere are refused.
fn workspace_path(path: &str) -> Result<PathBuf, String> {
    let relative = Path::new(path).strip_prefix(WORKSPACE).unwrap_or(Path::new(path));
    if relative.is_absolute() || relative.components().any(|c| matches!(c, Component::ParentDir | Component::RootDir | Component::Prefix(_))) {
        return Err(format!("{path}: only paths inside {WORKSPACE} are available"));
    }
    Ok(Path::new(WORKSPACE).join(relative))
}

fn tools() -> Value {
    let tool = |name: &str, description: &str, properties: Value, required: &[&str]| json!({
        "type": "function",
        "function": {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": required}}
    });
    json!([
        tool("list_dir", "List a directory in the workspace.", json!({"path": {"type": "string"}}), &["path"]),
        tool("read_file", "Read a text file from the workspace.", json!({"path": {"type": "string"}}), &["path"]),
        tool("write_file", "Write a text file in the workspace.", json!({"path": {"type": "string"}, "content": {"type": "string"}}), &["path", "content"]),
        tool("http_request", "Make an HTTP request. Only hosts in the policy are reachable; GET for reading, POST/PUT/PATCH/DELETE only to write hosts.",
            json!({"method": {"type": "string"}, "url": {"type": "string"}, "body": {"type": "string"}}), &["method", "url"]),
        tool("finish", "Finish the task with a short summary.", json!({"summary": {"type": "string"}}), &["summary"]),
    ])
}

fn run_tool(gateway: &mut Gateway, name: &str, args: &Value) -> String {
    let text = |key: &str| args[key].as_str().unwrap_or("").to_owned();
    let result = match name {
        "list_dir" => workspace_path(&text("path")).and_then(|p| fs::read_dir(&p).map_err(|e| e.to_string())).map(|entries| {
            let mut names: Vec<String> = entries.filter_map(Result::ok)
                .map(|e| format!("{}{}", e.file_name().to_string_lossy(), if e.path().is_dir() { "/" } else { "" })).collect();
            names.sort();
            names.join("\n")
        }),
        "read_file" => workspace_path(&text("path")).and_then(|p| fs::read_to_string(p).map_err(|e| e.to_string())),
        "write_file" => workspace_path(&text("path")).and_then(|p| {
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            fs::write(&p, text("content")).map(|()| format!("wrote {} bytes to {}", text("content").len(), p.display())).map_err(|e| e.to_string())
        }),
        "http_request" => {
            let reply = gateway.send(&json!({"op": "http", "method": text("method").to_uppercase(), "url": text("url"), "body": text("body")}));
            if reply["ok"] == true {
                let cut = if reply["truncated"] == true { " (the gateway kept only the start of the body)" } else { "" };
                Ok(format!("HTTP {}{cut}\n{}", reply["status"], reply["body"].as_str().unwrap_or("")))
            } else {
                Err(format!("request refused: {}", reply["error"].as_str().unwrap_or("denied")))
            }
        }
        "finish" => Ok(text("summary")),
        other => Err(format!("unknown tool {other}")),
    };
    clip(&result.unwrap_or_else(|e| format!("error: {e}")), MAX_TOOL_OUTPUT)
}

/// Tool calls from the message, or a single JSON call written as text by
/// models without native tool calling: {"tool": "...", "arguments": {...}}.
fn tool_calls(message: &Value) -> Vec<(String, String, Value)> {
    if let Some(calls) = message["tool_calls"].as_array().filter(|c| !c.is_empty()) {
        return calls.iter().map(|c| {
            let raw = &c["function"]["arguments"];
            let args = raw.as_str().and_then(|s| serde_json::from_str(s).ok()).unwrap_or_else(|| raw.clone());
            (c["id"].as_str().unwrap_or("call").to_owned(), c["function"]["name"].as_str().unwrap_or("").to_owned(), args)
        }).collect();
    }
    let content = message["content"].as_str().unwrap_or("");
    let (Some(start), Some(end)) = (content.find('{'), content.rfind('}')) else { return Vec::new() };
    let Ok(value) = serde_json::from_str::<Value>(&content[start..=end]) else { return Vec::new() };
    match value["tool"].as_str() {
        Some(name) => vec![("text-call".to_owned(), name.to_owned(), value.get("arguments").or(value.get("args")).cloned().unwrap_or(json!({})))],
        None => Vec::new(),
    }
}

pub fn run(gateway_path: &str, probe: &Value) -> Result<(), Box<dyn Error>> {
    let mut gateway = Gateway::connect(gateway_path)?;
    let task = probe["task"].as_str().unwrap_or("Summarise the files in /workspace.");
    let max_steps = probe["max_steps"].as_u64().unwrap_or(16);
    let mut messages = vec![
        json!({"role": "system", "content": format!(
            "You are an agent working in a sandbox. Your files are in {WORKSPACE}. Use the tools to complete the task, \
             then call finish with a short summary. Network access is limited to the hosts in the policy. \
             If your model cannot call tools natively, reply with one JSON object: {{\"tool\": NAME, \"arguments\": {{...}}}}.")}),
        json!({"role": "user", "content": task}),
    ];
    say("task", json!({"task": task, "max_steps": max_steps}));
    for step in 0..max_steps {
        let reply = gateway.send(&json!({"op": "infer", "messages": messages, "tools": tools()}));
        if reply["ok"] != true {
            say("infer_refused", json!({"step": step, "reply": reply}));
            break;
        }
        let message = reply["message"].clone();
        say("model", json!({"step": step, "message": message, "usage": reply["usage"]}));
        messages.push(json!({"role": "assistant", "content": message["content"].clone(), "tool_calls": message["tool_calls"].clone()}));
        let calls = tool_calls(&message);
        if calls.is_empty() {
            say("final", json!({"step": step, "content": message["content"]}));
            return Ok(());
        }
        for (id, name, args) in calls {
            let _ = gateway.send(&json!({"op": "log", "text": clip(&format!("tool {name} {args}"), 512)}));
            let output = run_tool(&mut gateway, &name, &args);
            say("tool", json!({"step": step, "name": name, "args": args, "output": clip(&output, 2_000)}));
            messages.push(json!({"role": "tool", "tool_call_id": id, "content": output}));
            if name == "finish" {
                say("final", json!({"step": step, "summary": args["summary"]}));
                return Ok(());
            }
        }
    }
    say("final", json!({"stopped": "step limit or refusal"}));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workspace_paths_stay_inside() {
        assert_eq!(workspace_path("notes.txt").unwrap(), PathBuf::from("/workspace/notes.txt"));
        assert_eq!(workspace_path("/workspace/a/b").unwrap(), PathBuf::from("/workspace/a/b"));
        for bad in ["../etc/passwd", "/etc/passwd", "a/../../x", "/workspace/../etc"] {
            assert!(workspace_path(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn parses_native_and_text_tool_calls() {
        let native = json!({"tool_calls": [{"id": "c1", "function": {"name": "read_file", "arguments": "{\"path\":\"a\"}"}}]});
        assert_eq!(tool_calls(&native), vec![("c1".into(), "read_file".into(), json!({"path": "a"}))]);
        let text = json!({"content": "Sure.\n{\"tool\": \"list_dir\", \"arguments\": {\"path\": \".\"}}"});
        assert_eq!(tool_calls(&text)[0].1, "list_dir");
        assert!(tool_calls(&json!({"content": "All done."})).is_empty());
    }
}
