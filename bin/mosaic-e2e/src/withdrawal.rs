//! Withdrawal mode — exercises the withdrawal flow on a deposit.

use anyhow::Result;
use jsonrpsee::http_client::HttpClient;

pub(crate) async fn run(client: &HttpClient) -> Result<()> {
    let _ = client;

    // TODO: mark_deposit_withdrawn or complete_adaptor_sigs + evaluate_tableset flow.

    Ok(())
}
