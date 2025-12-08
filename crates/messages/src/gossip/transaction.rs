//! Transaction gossip message.

use crate::trace_context::TraceContext;
use hyperscale_types::{NetworkMessage, RoutableTransaction, ShardMessage};
use sbor::prelude::BasicSbor;

/// Gossips a transaction to all shard groups with state touched by it.
/// Broadcast to union of write_shards (2PC consensus) and read_shards (provisioning).
#[derive(Debug, Clone, PartialEq, Eq, BasicSbor)]
pub struct TransactionGossip {
    /// The transaction being gossiped
    pub transaction: RoutableTransaction,
    /// Trace context for distributed tracing (empty when feature disabled).
    pub trace_context: TraceContext,
}

impl TransactionGossip {
    /// Create a new transaction gossip message.
    ///
    /// Does not capture trace context. Use `with_trace_context()` to include
    /// distributed tracing information.
    pub fn new(transaction: RoutableTransaction) -> Self {
        Self {
            transaction,
            trace_context: TraceContext::default(),
        }
    }

    /// Create a new transaction gossip message with trace context from current span.
    ///
    /// When `trace-propagation` feature is enabled, captures the current OpenTelemetry
    /// span context for distributed tracing across nodes.
    pub fn with_trace_context(transaction: RoutableTransaction) -> Self {
        Self {
            transaction,
            trace_context: TraceContext::from_current(),
        }
    }

    /// Get a reference to the inner transaction.
    pub fn transaction(&self) -> &RoutableTransaction {
        &self.transaction
    }

    /// Consume and return the inner transaction.
    pub fn into_transaction(self) -> RoutableTransaction {
        self.transaction
    }

    /// Get the trace context.
    pub fn trace_context(&self) -> &TraceContext {
        &self.trace_context
    }
}

// Network message implementation
impl NetworkMessage for TransactionGossip {
    fn message_type_id() -> &'static str {
        "transaction.gossip"
    }
}

// Transactions are filtered to shards that have state touched by the transaction
impl ShardMessage for TransactionGossip {}

#[cfg(test)]
mod tests {
    use super::*;

    use hyperscale_types::test_utils::{test_node, test_transaction_with_nodes};

    #[test]
    fn test_transaction_gossip_creation() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip = TransactionGossip::new(tx.clone());
        assert_eq!(gossip.transaction().hash(), tx.hash());
    }

    #[test]
    fn test_transaction_gossip_into_transaction() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![], vec![test_node(1)]);

        let hash = tx.hash();
        let gossip = TransactionGossip::new(tx);
        let extracted = gossip.into_transaction();
        assert_eq!(extracted.hash(), hash);
    }

    #[test]
    fn test_transaction_gossip_hash_consistency() {
        let tx1 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);
        let tx2 = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        let gossip1 = TransactionGossip::new(tx1);
        let gossip2 = TransactionGossip::new(tx2);

        // Same data should produce same transaction hash
        assert_eq!(gossip1.transaction().hash(), gossip2.transaction().hash());
    }

    #[test]
    fn test_transaction_gossip_trace_context() {
        let tx = test_transaction_with_nodes(&[1, 2, 3], vec![test_node(1)], vec![test_node(2)]);

        // new() should have empty trace context
        let gossip = TransactionGossip::new(tx.clone());
        assert!(!gossip.trace_context().has_trace());

        // with_trace_context() without active span should also be empty
        let gossip_with_ctx = TransactionGossip::with_trace_context(tx);
        // When no span is active, trace context will be empty
        assert!(!gossip_with_ctx.trace_context().has_trace() || TraceContext::is_enabled());
    }
}
