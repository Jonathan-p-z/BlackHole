use clap::Parser;

#[derive(Parser)]
#[command(
    name = "blackhole-dashboard",
    about = "Real-time BlackHole status dashboard"
)]
struct Cli {
    /// Use synthetic, fabricated data instead of the real blackhole-core /
    /// blackhole-dns modules. Useful for UI development and demos.
    #[arg(long)]
    mock: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    blackhole_dashboard::run(cli.mock).await
}
