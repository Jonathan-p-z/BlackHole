//! Real-time BlackHole status dashboard: a `ratatui` TUI polling
//! `blackhole-core`/`blackhole-dns` on a fixed interval, plus a panic-mode
//! key (force the kill switch on immediately). [`run`] is the one entry
//! point both this crate's own binary and any other orchestrator (e.g.
//! `blackhole-cli`'s `dashboard` subcommand) call: the TUI event loop
//! lives here exactly once, never duplicated.

pub mod app;
pub mod backend;
pub mod data;
pub mod ui;

use std::time::Duration;

use crossterm::event::{Event, EventStream, KeyCode, KeyEventKind};
use futures_util::StreamExt;
use tokio::sync::mpsc;

use app::App;
use backend::Command;
use data::{DataSource, LiveDataSource, MockDataSource};

/// Run the dashboard TUI until the user quits (`q`/Esc) or the terminal
/// event stream ends. `mock` selects synthetic demo data instead of the
/// real blackhole-core/blackhole-dns modules.
pub async fn run(mock: bool) -> anyhow::Result<()> {
    let source: Box<dyn DataSource> = if mock {
        Box::new(MockDataSource::new())
    } else {
        Box::new(LiveDataSource::new())
    };

    let (snapshot_tx, snapshot_rx) = mpsc::channel(8);
    let (command_tx, command_rx) = mpsc::channel(4);

    let backend_handle = tokio::spawn(backend::run(source, snapshot_tx, command_rx));

    let mut terminal = ratatui::init();
    let result = run_ui(&mut terminal, snapshot_rx, command_tx).await;
    ratatui::restore();

    backend_handle.abort();
    result
}

async fn run_ui(
    terminal: &mut ratatui::DefaultTerminal,
    mut snapshot_rx: mpsc::Receiver<app::Snapshot>,
    command_tx: mpsc::Sender<Command>,
) -> anyhow::Result<()> {
    let mut app = App::new();
    let mut events = EventStream::new();
    let mut render_tick = tokio::time::interval(Duration::from_millis(500));

    terminal.draw(|frame| ui::draw(frame, &app))?;

    loop {
        tokio::select! {
            Some(snapshot) = snapshot_rx.recv() => {
                app.panic_in_flight = false;
                app.apply(snapshot);
                terminal.draw(|frame| ui::draw(frame, &app))?;
            }
            maybe_event = events.next() => {
                match maybe_event {
                    Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => {
                        match key.code {
                            KeyCode::Char('q') | KeyCode::Esc => {
                                app.should_quit = true;
                            }
                            KeyCode::Char('p') | KeyCode::Char('P') => {
                                app.panic_in_flight = true;
                                let _ = command_tx.send(Command::Panic).await;
                            }
                            _ => {}
                        }
                        terminal.draw(|frame| ui::draw(frame, &app))?;
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {
                        app.should_quit = true;
                    }
                }
            }
            _ = render_tick.tick() => {
                app.expire_banner();
                terminal.draw(|frame| ui::draw(frame, &app))?;
            }
        }

        if app.should_quit {
            return Ok(());
        }
    }
}
