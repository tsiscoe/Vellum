//! Ratatui v0.30+ 3-pane interactive Vellum Custody & Wireframe Console (`vellum tui`).

pub mod ui;

use std::io;
use std::time::Duration;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};

use crate::vault::{AuditChainReport, ScopeKeySummary, SealAuditEntry};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivePane {
    Scopes,
    Wireframe,
    AuditLog,
}

pub struct VellumTuiApp {
    pub vault_path: String,
    pub scopes: Vec<ScopeKeySummary>,
    pub audit_entries: Vec<SealAuditEntry>,
    pub chain_report: AuditChainReport,
    pub wire_file_label: String,
    pub wire_chunk_count: usize,
    pub wire_seal_hex: String,
    pub wire_chunk_ids: Vec<String>,
    pub active_pane: ActivePane,
    pub selected_scope: usize,
    pub selected_chunk: usize,
    pub selected_audit: usize,
}

impl VellumTuiApp {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        vault_path: String,
        scopes: Vec<ScopeKeySummary>,
        audit_entries: Vec<SealAuditEntry>,
        chain_report: AuditChainReport,
        wire_file_label: String,
        wire_chunk_count: usize,
        wire_seal_hex: String,
        wire_chunk_ids: Vec<String>,
    ) -> Self {
        Self {
            vault_path,
            scopes,
            audit_entries,
            chain_report,
            wire_file_label,
            wire_chunk_count,
            wire_seal_hex,
            wire_chunk_ids,
            active_pane: ActivePane::Scopes,
            selected_scope: 0,
            selected_chunk: 0,
            selected_audit: 0,
        }
    }

    pub fn next_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Scopes => ActivePane::Wireframe,
            ActivePane::Wireframe => ActivePane::AuditLog,
            ActivePane::AuditLog => ActivePane::Scopes,
        };
    }

    pub fn prev_pane(&mut self) {
        self.active_pane = match self.active_pane {
            ActivePane::Scopes => ActivePane::AuditLog,
            ActivePane::Wireframe => ActivePane::Scopes,
            ActivePane::AuditLog => ActivePane::Wireframe,
        };
    }

    pub fn move_down(&mut self) {
        match self.active_pane {
            ActivePane::Scopes if !self.scopes.is_empty() => {
                self.selected_scope = (self.selected_scope + 1) % self.scopes.len();
            }
            ActivePane::Wireframe if !self.wire_chunk_ids.is_empty() => {
                self.selected_chunk = (self.selected_chunk + 1) % self.wire_chunk_ids.len();
            }
            ActivePane::AuditLog if !self.audit_entries.is_empty() => {
                self.selected_audit = (self.selected_audit + 1) % self.audit_entries.len();
            }
            _ => {}
        }
    }

    pub fn move_up(&mut self) {
        match self.active_pane {
            ActivePane::Scopes if !self.scopes.is_empty() => {
                self.selected_scope = self
                    .selected_scope
                    .checked_sub(1)
                    .unwrap_or(self.scopes.len() - 1);
            }
            ActivePane::Wireframe if !self.wire_chunk_ids.is_empty() => {
                self.selected_chunk = self
                    .selected_chunk
                    .checked_sub(1)
                    .unwrap_or(self.wire_chunk_ids.len() - 1);
            }
            ActivePane::AuditLog if !self.audit_entries.is_empty() => {
                self.selected_audit = self
                    .selected_audit
                    .checked_sub(1)
                    .unwrap_or(self.audit_entries.len() - 1);
            }
            _ => {}
        }
    }
}

fn install_terminal_panic_hook() {
    let prev = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        prev(info);
    }));
}

pub fn run_interactive_tui(mut app: VellumTuiApp) -> Result<()> {
    install_terminal_panic_hook();
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = (|| -> Result<()> {
        loop {
            terminal.draw(|frame| ui::render(frame, &app))?;
            if event::poll(Duration::from_millis(100))?
                && let Event::Key(key) = event::read()?
                && key.kind == KeyEventKind::Press
            {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Tab => app.next_pane(),
                    KeyCode::BackTab => app.prev_pane(),
                    KeyCode::Down | KeyCode::Char('j') => app.move_down(),
                    KeyCode::Up | KeyCode::Char('k') => app.move_up(),
                    _ => {}
                }
            }
        }
        Ok(())
    })();

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;
    res
}
