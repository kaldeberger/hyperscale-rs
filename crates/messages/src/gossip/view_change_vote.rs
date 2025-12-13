//! ViewChangeVote gossip message.

use hyperscale_types::{NetworkMessage, ShardMessage};
use sbor::prelude::BasicSbor;

// Re-export ViewChangeVote from types for convenience
pub use hyperscale_types::ViewChangeVote;

/// Vote to trigger a view change. 2f+1 votes for same (height, round) advance all validators.
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct ViewChangeVoteGossip {
    /// The view change vote being gossiped
    pub vote: ViewChangeVote,
    /// Nonce to allow rebroadcasting the same vote with a unique message ID.
    /// Gossipsub deduplicates by message content, so we need this to vary
    /// when rebroadcasting to handle message loss. The vote signature remains
    /// valid regardless of this nonce value.
    pub broadcast_nonce: u64,
}

impl ViewChangeVoteGossip {
    /// Create a new view change vote gossip message with nonce 0.
    pub fn new(vote: ViewChangeVote) -> Self {
        Self {
            vote,
            broadcast_nonce: 0,
        }
    }

    /// Create a new view change vote gossip message with a specific nonce.
    pub fn with_nonce(vote: ViewChangeVote, nonce: u64) -> Self {
        Self {
            vote,
            broadcast_nonce: nonce,
        }
    }

    /// Get the inner view change vote.
    pub fn vote(&self) -> &ViewChangeVote {
        &self.vote
    }

    /// Consume and return the inner view change vote.
    pub fn into_vote(self) -> ViewChangeVote {
        self.vote
    }
}

impl NetworkMessage for ViewChangeVoteGossip {
    fn message_type_id() -> &'static str {
        "view_change.vote"
    }
}

impl ShardMessage for ViewChangeVoteGossip {}
