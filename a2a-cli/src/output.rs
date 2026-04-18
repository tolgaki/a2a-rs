use a2a_rs_core::{AgentCard, Message, Role, StreamingMessageResult, Task, TaskListResponse};
use anyhow::Result;
use serde::Serialize;

pub struct Renderer {
    pub json: bool,
}

impl Renderer {
    pub fn new(json: bool) -> Self {
        Self { json }
    }

    pub fn emit<T: Serialize>(&self, value: &T) -> Result<()> {
        if self.json {
            println!("{}", serde_json::to_string_pretty(value)?);
        }
        Ok(())
    }

    pub fn card(&self, card: &AgentCard) -> Result<()> {
        if self.json {
            return self.emit(card);
        }
        println!("{}", card.name);
        println!("  description : {}", card.description);
        println!("  version     : {}", card.version);
        if let Some(p) = &card.provider {
            println!("  provider    : {} <{}>", p.organization, p.url);
        }
        if let Some(ep) = card.endpoint() {
            println!("  endpoint    : {}", ep);
        }
        println!(
            "  capabilities: streaming={} push={} extended={}",
            card.capabilities.streaming.unwrap_or(false),
            card.capabilities.push_notifications.unwrap_or(false),
            card.capabilities.extended_agent_card.unwrap_or(false),
        );
        if !card.skills.is_empty() {
            println!("  skills:");
            for s in &card.skills {
                println!("    - {} ({}): {}", s.name, s.id, s.description);
            }
        }
        Ok(())
    }

    pub fn task(&self, task: &Task) -> Result<()> {
        if self.json {
            return self.emit(task);
        }
        println!("Task {}", task.id);
        println!("  context : {}", task.context_id);
        println!("  state   : {:?}", task.status.state);
        if let Some(ts) = &task.status.timestamp {
            println!("  updated : {}", ts);
        }
        if let Some(msg) = &task.status.message {
            print_message_body("  status  : ", msg);
        }
        if let Some(history) = &task.history {
            println!("  history ({} msgs):", history.len());
            for m in history {
                let who = match m.role {
                    Role::User => "user",
                    Role::Agent => "agent",
                    _ => "?",
                };
                for p in &m.parts {
                    if let Some(t) = p.as_text() {
                        println!("    [{who}] {t}");
                    }
                }
            }
        }
        if let Some(artifacts) = &task.artifacts {
            if !artifacts.is_empty() {
                println!("  artifacts:");
                for a in artifacts {
                    let name = a.name.as_deref().unwrap_or("(unnamed)");
                    println!("    - {name}: {} part(s)", a.parts.len());
                }
            }
        }
        Ok(())
    }

    pub fn task_list(&self, list: &TaskListResponse) -> Result<()> {
        if self.json {
            return self.emit(list);
        }
        println!(
            "{} task(s) (total {}, page_size {})",
            list.tasks.len(),
            list.total_size,
            list.page_size
        );
        for t in &list.tasks {
            println!("  - {}  [{:?}]  ctx={}", t.id, t.status.state, t.context_id);
        }
        if !list.next_page_token.is_empty() {
            println!("  next_page_token: {}", list.next_page_token);
        }
        Ok(())
    }

    pub fn message(&self, msg: &Message) -> Result<()> {
        if self.json {
            return self.emit(msg);
        }
        print_message_body("agent: ", msg);
        Ok(())
    }

    pub fn stream_event(&self, ev: &StreamingMessageResult) -> Result<()> {
        if self.json {
            return self.emit(ev);
        }
        match ev {
            StreamingMessageResult::Task(t) => {
                println!("[task] id={} state={:?}", t.id, t.status.state);
            }
            StreamingMessageResult::Message(m) => {
                print_message_body("[message] ", m);
            }
            StreamingMessageResult::StatusUpdate(u) => {
                println!(
                    "[status] task={} state={:?}",
                    u.task_id, u.status.state
                );
                if let Some(m) = &u.status.message {
                    print_message_body("  ", m);
                }
            }
            StreamingMessageResult::ArtifactUpdate(u) => {
                let name = u.artifact.name.as_deref().unwrap_or("(unnamed)");
                let last = u.last_chunk.unwrap_or(false);
                let mut text = String::new();
                for p in &u.artifact.parts {
                    if let Some(t) = p.as_text() {
                        text.push_str(t);
                    }
                }
                println!(
                    "[artifact] {}{} -> {}",
                    name,
                    if last { " (last)" } else { "" },
                    text
                );
            }
        }
        Ok(())
    }
}

fn print_message_body(prefix: &str, msg: &Message) {
    let mut first = true;
    for p in &msg.parts {
        if let Some(t) = p.as_text() {
            if first {
                println!("{prefix}{t}");
                first = false;
            } else {
                println!("{}{t}", " ".repeat(prefix.len()));
            }
        }
    }
}
