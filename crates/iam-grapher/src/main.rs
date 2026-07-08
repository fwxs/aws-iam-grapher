mod cli;
mod output;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // RUST_LOG, when set, takes full control (e.g. `RUST_LOG=iam_collector=debug`) — our
    // defaults below only apply when the user hasn't opted into their own filter, otherwise a
    // same-target default directive would always win ties against the user's own.
    let filter = if std::env::var("RUST_LOG").is_ok() {
        tracing_subscriber::EnvFilter::from_default_env()
    } else {
        tracing_subscriber::EnvFilter::new("")
            .add_directive("aws_iam_grapher=info".parse()?)
            .add_directive("iam_collector=info".parse()?)
            .add_directive("iam_graph=info".parse()?)
    };

    tracing_subscriber::fmt().with_env_filter(filter).init();

    cli::run().await
}
