use std::time::Duration;

use tokio::sync::mpsc;

use crate::app::Snapshot;
use crate::data::DataSource;

pub enum Command {
    Panic,
}

/// Owns the [`DataSource`] and drives it on a fixed interval, plus
/// on-demand for panic mode. Runs on its own tokio task so a slow module
/// (a stuck Tor bootstrap, a hanging DNS query) never blocks the UI's
/// render/input loop.
pub async fn run(
    mut source: Box<dyn DataSource>,
    tx: mpsc::Sender<Snapshot>,
    mut commands: mpsc::Receiver<Command>,
) {
    let mut ticker = tokio::time::interval(Duration::from_secs(3));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                let snapshot = source.poll().await;
                if tx.send(snapshot).await.is_err() {
                    return; // UI side hung up.
                }
            }
            cmd = commands.recv() => {
                match cmd {
                    Some(Command::Panic) => {
                        let snapshot = source.panic().await;
                        if tx.send(snapshot).await.is_err() {
                            return;
                        }
                    }
                    None => return, // UI side hung up.
                }
            }
        }
    }
}
