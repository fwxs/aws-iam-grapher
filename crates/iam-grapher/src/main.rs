mod cli;
mod output;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("aws_iam_grapher=info".parse()?),
        )
        .init();

    cli::run().await
}
