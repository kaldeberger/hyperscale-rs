//! Network messages for the consensus protocol.

pub mod gossip;
pub mod request;
pub mod response;
pub mod trace_context;

// Re-export commonly used types
pub use gossip::{
    BlockHeaderGossip, BlockVoteGossip, StateCertificateGossip, StateProvisionGossip,
    StateVoteBlockGossip, TransactionGossip, ViewChangeCertificateGossip, ViewChangeVote,
    ViewChangeVoteGossip,
};
pub use request::{GetBlockInventoryRequest, GetBlockRequest, SyncCompleteAnnouncement};
pub use response::{GetBlockInventoryResponse, GetBlockResponse};
pub use trace_context::TraceContext;
