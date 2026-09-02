use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Gauge, Paragraph, Wrap};

use crate::app::{App, Danger, DnsInfo, KillSwitchInfo, ModuleState, TorInfo};

const GREEN: Color = Color::Green;
const RED: Color = Color::Red;
const YELLOW: Color = Color::Yellow;
const GRAY: Color = Color::DarkGray;

pub fn draw(frame: &mut Frame, app: &App) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header / overall status
            Constraint::Min(10),   // panels
            Constraint::Length(3), // help line
        ])
        .split(frame.area());

    draw_header(frame, root[0], app);

    let panels = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(34),
            Constraint::Percentage(33),
            Constraint::Percentage(33),
        ])
        .split(root[1]);

    draw_kill_switch(frame, panels[0], &app.snapshot.kill_switch);
    draw_tor(frame, panels[1], &app.snapshot.tor);
    draw_dns(frame, panels[2], &app.snapshot.dns);

    draw_help(frame, root[2], app);

    if let Some(banner) = &app.snapshot.banner {
        draw_banner(frame, banner);
    }
}

fn danger_color(danger: Danger) -> Color {
    match danger {
        Danger::Protected => GREEN,
        Danger::Warning => YELLOW,
        Danger::Danger => RED,
    }
}

fn draw_header(frame: &mut Frame, area: Rect, app: &App) {
    let danger = app.snapshot.danger();
    let color = danger_color(danger);
    let label = match danger {
        Danger::Protected => "PROTECTED",
        Danger::Warning => "WARNING",
        Danger::Danger => "DANGER",
    };

    let text = Line::from(vec![
        Span::styled(
            " BlackHole ",
            Style::default()
                .fg(Color::Black)
                .bg(color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(
            label,
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        ),
    ]);

    let paragraph = Paragraph::new(text)
        .block(Block::default().borders(Borders::ALL))
        .alignment(Alignment::Left);
    frame.render_widget(paragraph, area);
}

fn unavailable_paragraph(title: &str, reason: &str) -> Paragraph<'static> {
    Paragraph::new(format!("module non détecté\n\n{reason}"))
        .style(Style::default().fg(GRAY))
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(Style::default().fg(GRAY)),
        )
}

fn initializing_paragraph(title: &str) -> Paragraph<'static> {
    Paragraph::new("initialisation...")
        .style(Style::default().fg(YELLOW))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title.to_string())
                .border_style(Style::default().fg(YELLOW)),
        )
}

fn draw_kill_switch(frame: &mut Frame, area: Rect, state: &ModuleState<KillSwitchInfo>) {
    match state {
        ModuleState::Initializing => {
            frame.render_widget(initializing_paragraph("Kill Switch"), area)
        }
        ModuleState::Unavailable(reason) => {
            frame.render_widget(unavailable_paragraph("Kill Switch", reason), area)
        }
        ModuleState::Ok(info) => {
            let color = match info.state.as_str() {
                "enabled" => GREEN,
                "faulted" => RED,
                _ => YELLOW,
            };
            let lines = vec![
                Line::from(vec![
                    Span::raw("state:   "),
                    Span::styled(
                        info.state.clone(),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(format!(
                    "egress:  {}",
                    info.allowed_egress.as_deref().unwrap_or("(unknown)")
                )),
            ];
            let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("Kill Switch")
                    .border_style(Style::default().fg(color)),
            );
            frame.render_widget(paragraph, area);
        }
    }
}

fn draw_tor(frame: &mut Frame, area: Rect, state: &ModuleState<TorInfo>) {
    match state {
        ModuleState::Initializing => frame.render_widget(initializing_paragraph("Tor"), area),
        ModuleState::Unavailable(reason) => {
            frame.render_widget(unavailable_paragraph("Tor", reason), area)
        }
        ModuleState::Ok(info) => {
            let color = if info.ready_for_traffic {
                GREEN
            } else {
                YELLOW
            };
            let inner = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(3), Constraint::Min(1)])
                .split(area);

            let gauge = Gauge::default()
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title("Tor")
                        .border_style(Style::default().fg(color)),
                )
                .gauge_style(Style::default().fg(color))
                .percent(info.bootstrap_percent as u16)
                .label(format!("{}%", info.bootstrap_percent));
            frame.render_widget(gauge, inner[0]);

            let lines = vec![
                Line::from(format!(
                    "status:   {}",
                    if info.ready_for_traffic {
                        "connected"
                    } else {
                        "bootstrapping"
                    }
                )),
                Line::from(format!(
                    "exit ip:  {}",
                    info.exit_ip
                        .map(|ip| ip.to_string())
                        .unwrap_or_else(|| "(unknown)".to_string())
                )),
            ];
            frame.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }), inner[1]);
        }
    }
}

fn draw_dns(frame: &mut Frame, area: Rect, state: &ModuleState<DnsInfo>) {
    match state {
        ModuleState::Initializing => frame.render_widget(initializing_paragraph("DNS"), area),
        ModuleState::Unavailable(reason) => {
            frame.render_widget(unavailable_paragraph("DNS", reason), area)
        }
        ModuleState::Ok(info) => {
            let color = if info.leak_detected { RED } else { GREEN };
            let mut lines = vec![
                Line::from(format!("resolver: {}", info.provider)),
                Line::from(vec![
                    Span::raw("leak:     "),
                    Span::styled(
                        if info.leak_detected { "YES" } else { "no" },
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                ]),
                Line::from(format!(
                    "latency:  {}",
                    info.latency_ms
                        .map(|l| format!("{l} ms"))
                        .unwrap_or_else(|| "(n/a)".to_string())
                )),
            ];
            if info.leak_detected && !info.leaking_servers.is_empty() {
                lines.push(Line::from(format!(
                    "via:      {}",
                    info.leaking_servers
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            let paragraph = Paragraph::new(lines).wrap(Wrap { trim: true }).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title("DNS")
                    .border_style(Style::default().fg(color)),
            );
            frame.render_widget(paragraph, area);
        }
    }
}

fn draw_help(frame: &mut Frame, area: Rect, app: &App) {
    let text = if app.panic_in_flight {
        Line::from(Span::styled(
            " triggering panic mode... ",
            Style::default()
                .fg(Color::Black)
                .bg(RED)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        Line::from(vec![
            Span::styled(
                " p ",
                Style::default()
                    .fg(Color::Black)
                    .bg(RED)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" panic mode (force kill switch)    "),
            Span::styled(
                " q ",
                Style::default()
                    .fg(Color::Black)
                    .bg(GRAY)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw(" quit"),
        ])
    };
    frame.render_widget(
        Paragraph::new(text).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn draw_banner(frame: &mut Frame, message: &str) {
    let area = frame.area();
    let width = (area.width.saturating_sub(4)).clamp(20, 60);
    let height = 5u16;
    let popup = Rect {
        x: area.x + (area.width.saturating_sub(width)) / 2,
        y: area.y + (area.height.saturating_sub(height)) / 2,
        width,
        height,
    };

    let danger = message.contains("FAILED");
    let color = if danger { RED } else { GREEN };

    let paragraph = Paragraph::new(message)
        .style(Style::default().fg(color).add_modifier(Modifier::BOLD))
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Panic Mode")
                .border_style(Style::default().fg(color)),
        );

    frame.render_widget(ratatui::widgets::Clear, popup);
    frame.render_widget(paragraph, popup);
}
