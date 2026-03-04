mod formatting;
mod indicator;
mod otx_client;
mod tools;

use std::sync::Arc;

use rmcp::ServiceExt;

use otx_client::OtxClient;
use tools::OtxTools;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt().with_env_filter("info").init();
    let client = OtxClient::new()?;
    let handler = OtxTools::new(Arc::new(client));
    let transport = (tokio::io::stdin(), tokio::io::stdout());
    let server = handler.serve(transport).await?;
    server.waiting().await?;
    Ok(())
}
