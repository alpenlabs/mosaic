//! Node-level status types returned by the admin RPC.

use serde::{Deserialize, Serialize};

/// Identity / version information about a running mosaic node.
///
/// Returned by the `mosaic_nodeInfo` RPC. Operators can use this to verify
/// that two nodes are on compatible builds and the same deployment cohort
/// without diving into logs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RpcNodeInfo {
    /// Hex-encoded Ed25519 peer id of this node.
    pub peer_id_hex: String,
    /// Protocol version this node advertises in the peer-to-peer
    /// version handshake. Same value on both peers is a prerequisite for any
    /// communication to succeed.
    pub protocol_version: u32,
    /// Deployment-cohort identifier exchanged in the handshake. `None` for
    /// uncoordinated dev nodes; `Some` for coordinated deployments where every
    /// operator must set the same value (e.g. `"tn3"`).
    pub deployment_version: Option<String>,
}
