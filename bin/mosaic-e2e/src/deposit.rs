//! Deposit mode — initialises a deposit on a tableset.

use anyhow::Result;
use jsonrpsee::http_client::HttpClient;

pub(crate) async fn run(client: &HttpClient) -> Result<()> {
    let _ = client;

    // TODO: init_garbler_deposit / init_evaluator_deposit and poll deposit status.

    Ok(())
}
