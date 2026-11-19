//! Ratatui v0.30+ 3-pane layout and ANSI/OSC escape-sanitized renderer (`CWE-150`) for **Vellum**.

use ratatui::{
    Frame,
    layout::{Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Cell, Paragraph, Row, Table, Wrap},
};

use crate::tui::{ActivePane, VellumTuiApp};

/// Strip C0/C1 control characters and ANSI/OSC escape sequences (`\x1b`) before rendering
/// repository paths or metadata into the terminal buffer (`CWE-150`).
pub fn sanitize_terminal_str(input: &str) -> String {
    input
        .chars()
        .filter(|&c| c == '\n' || c == '\t' || (!c.is_control() && c != '\u{001b}'))
        .collect()
}

pub fn render(frame: &mut Frame, app: &VellumTuiApp) {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Length(4),
            Constraint::Percentage(46),
            Constraint::Percentage(40),
            Constraint::Length(2),
        ])
        .split(frame.area());

    let chain_badge = if app.chain_report.valid {
        Span::styled(
            " MERKLE AUDIT: VERIFIED ",
            Style::default()
                .fg(Color::Black)
                .bg(Color::Green)
                .add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(
            " MERKLE AUDIT: TAMPERED ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        )
    };

    let masthead = Paragraph::new(Line::from(vec![
        Span::styled(
            " VELLUM v0.1.0 ",
            Style::default()
                .fg(Color::White)
                .bg(Color::Red)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw(" // "),
        Span::styled(
            "CHUNK-CONVERGENT BLAKE3-XCHACHA20-SIV GIT FILTER & MERGE  ",
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        ),
        chain_badge,
    ]))
    .block(Block::default().borders(Borders::ALL));
    frame.render_widget(masthead, vertical[0]);

    let head_short = if app.chain_report.head_hash.len() >= 16 {
        &app.chain_report.head_hash[..16]
    } else {
        &app.chain_report.head_hash
    };
    let telemetry_text = format!(
        "Vault: {}   |   Repo Scopes: {}   |   Audit Events: {} (head: {}...)\nCipher: TextBlocks + Keyed Gear-CDC -> BLAKE3-XChaCha20-SIV + File Merkle Seal",
        sanitize_terminal_str(&app.vault_path),
        app.scopes.len(),
        app.audit_entries.len(),
        head_short,
    );
    let telemetry = Paragraph::new(telemetry_text).block(
        Block::default()
            .title(" [00] CUSTODY & SIV CONVERGENCE TELEMETRY ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    frame.render_widget(telemetry, vertical[1]);

    let mid_cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
        .split(vertical[2]);

    let scope_border = if app.active_pane == ActivePane::Scopes {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let scope_rows: Vec<Row> = app
        .scopes
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let style = if i == app.selected_scope && app.active_pane == ActivePane::Scopes {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![
                Cell::from(sanitize_terminal_str(&s.scope)),
                Cell::from(sanitize_terminal_str(&s.fingerprint)),
                Cell::from(sanitize_terminal_str(&s.created_at)),
            ])
            .style(style)
        })
        .collect();

    let scope_table = Table::new(
        scope_rows,
        [
            Constraint::Length(16),
            Constraint::Length(14),
            Constraint::Percentage(50),
        ],
    )
    .header(
        Row::new(["SCOPE", "KEY FINGERPRINT", "PROVISIONED UTC"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" [01] SCOPED REPOSITORY KEYS ")
            .borders(Borders::ALL)
            .border_style(scope_border),
    );
    frame.render_widget(scope_table, mid_cols[0]);

    let wire_border = if app.active_pane == ActivePane::Wireframe {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let selected_chunk_preview = app
        .wire_chunk_ids
        .get(app.selected_chunk)
        .map(|id| {
            format!(
                "chunk[{}]={}",
                app.selected_chunk,
                sanitize_terminal_str(id)
            )
        })
        .unwrap_or_else(|| "no chunks loaded".to_string());
    let wire_body = format!(
        "Target Wireframe: {}\nChunk Count: {}\nMerkle Seal: {}\nSelected Node: {}",
        sanitize_terminal_str(&app.wire_file_label),
        app.wire_chunk_count,
        sanitize_terminal_str(&app.wire_seal_hex),
        selected_chunk_preview
    );
    let wire_pane = Paragraph::new(wire_body).wrap(Wrap { trim: false }).block(
        Block::default()
            .title(" [02] WIREFRAME CHUNK & MERKLE SEAL INSPECTOR ")
            .borders(Borders::ALL)
            .border_style(wire_border),
    );
    frame.render_widget(wire_pane, mid_cols[1]);

    let audit_border = if app.active_pane == ActivePane::AuditLog {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let audit_rows: Vec<Row> = app
        .audit_entries
        .iter()
        .enumerate()
        .map(|(i, a)| {
            let style = if i == app.selected_audit && app.active_pane == ActivePane::AuditLog {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            let hash_short = if a.entry_hash.len() >= 12 {
                &a.entry_hash[..12]
            } else {
                &a.entry_hash
            };
            Row::new(vec![
                Cell::from(format!("#{}", a.seq)),
                Cell::from(sanitize_terminal_str(&a.operation)),
                Cell::from(sanitize_terminal_str(&a.scope)),
                Cell::from(sanitize_terminal_str(&a.rel_path)),
                Cell::from(format!("{}/{}", a.unchanged_chunks, a.total_chunks)),
                Cell::from(sanitize_terminal_str(hash_short)),
            ])
            .style(style)
        })
        .collect();

    let audit_table = Table::new(
        audit_rows,
        [
            Constraint::Length(6),
            Constraint::Length(14),
            Constraint::Length(12),
            Constraint::Percentage(36),
            Constraint::Length(10),
            Constraint::Length(14),
        ],
    )
    .header(
        Row::new(["SEQ", "OP", "SCOPE", "PATH", "REUSE", "BLAKE3"]).style(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        ),
    )
    .block(
        Block::default()
            .title(" [03] BLAKE3 MERKLE FILTER & MERGE AUDIT LOG ")
            .borders(Borders::ALL)
            .border_style(audit_border),
    );
    frame.render_widget(audit_table, vertical[3]);

    let footer = Paragraph::new(
        "Keys: [Tab/Shift-Tab] Switch Pane  |  [j/k / Arrows] Navigate  |  [q / Esc] Quit",
    )
    .style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, vertical[4]);
}
