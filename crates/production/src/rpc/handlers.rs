//! HTTP request handlers for the RPC API.

use super::types::*;
use crate::sync::SyncStatus;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use hyperscale_core::TransactionStatus;
use hyperscale_types::{Hash, RoutableTransaction, TransactionDecision};
use prometheus::{Encoder, TextEncoder};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, RwLock};

/// Shared state for RPC handlers.
#[derive(Clone)]
pub struct RpcState {
    /// Ready flag for readiness probe.
    pub ready: Arc<AtomicBool>,
    /// Sync status provider.
    pub sync_status: Arc<RwLock<SyncStatus>>,
    /// Node status provider.
    pub node_status: Arc<RwLock<NodeStatusState>>,
    /// Channel to submit transactions to the node.
    pub tx_sender: mpsc::Sender<RoutableTransaction>,
    /// Server start time for uptime calculation.
    pub start_time: Instant,
    /// Transaction status cache for querying transaction state.
    pub tx_status_cache: Arc<RwLock<TransactionStatusCache>>,
    /// Mempool snapshot for querying mempool stats.
    pub mempool_snapshot: Arc<RwLock<MempoolSnapshot>>,
}

/// Cached transaction status entry.
#[derive(Debug, Clone)]
pub struct CachedTransactionStatus {
    /// Current status of the transaction.
    pub status: TransactionStatus,
    /// When this entry was last updated.
    pub updated_at: Instant,
}

impl CachedTransactionStatus {
    /// Create a new cached status entry.
    pub fn new(status: TransactionStatus) -> Self {
        Self {
            status,
            updated_at: Instant::now(),
        }
    }
}

/// Cache of transaction statuses for RPC queries.
///
/// This cache is updated by the runner when processing `EmitTransactionStatus` actions.
/// Entries are kept for a configurable TTL to allow status queries after completion.
#[derive(Debug, Default)]
pub struct TransactionStatusCache {
    /// Map of transaction hash to cached status.
    entries: HashMap<Hash, CachedTransactionStatus>,
    /// Maximum number of entries to keep (prevents unbounded growth).
    max_entries: usize,
    /// TTL for completed transaction entries.
    completed_ttl: Duration,
}

impl TransactionStatusCache {
    /// Create a new cache with default settings.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            max_entries: 100_000,
            completed_ttl: Duration::from_secs(300), // 5 minutes
        }
    }

    /// Create a new cache with custom settings.
    pub fn with_config(max_entries: usize, completed_ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            completed_ttl,
        }
    }

    /// Update or insert a transaction status.
    pub fn update(&mut self, tx_hash: Hash, status: TransactionStatus) {
        // If at capacity and this is a new entry, evict old completed entries first
        if self.entries.len() >= self.max_entries && !self.entries.contains_key(&tx_hash) {
            self.evict_old_entries();
        }

        self.entries
            .insert(tx_hash, CachedTransactionStatus::new(status));
    }

    /// Get the status of a transaction.
    pub fn get(&self, tx_hash: &Hash) -> Option<&CachedTransactionStatus> {
        self.entries.get(tx_hash)
    }

    /// Evict old completed entries to make room for new ones.
    fn evict_old_entries(&mut self) {
        let now = Instant::now();
        let ttl = self.completed_ttl;

        // Remove entries that are completed/retried and older than TTL
        self.entries.retain(|_, entry| {
            let is_terminal = entry.status.is_final();
            let is_old = now.duration_since(entry.updated_at) > ttl;
            !(is_terminal && is_old)
        });

        // If still at capacity, remove oldest terminal entries
        if self.entries.len() >= self.max_entries {
            let mut terminal_entries: Vec<_> = self
                .entries
                .iter()
                .filter(|(_, e)| e.status.is_final())
                .map(|(h, e)| (*h, e.updated_at))
                .collect();

            terminal_entries.sort_by_key(|(_, t)| *t);

            // Remove oldest 10% of terminal entries
            let to_remove = terminal_entries.len() / 10 + 1;
            for (hash, _) in terminal_entries.into_iter().take(to_remove) {
                self.entries.remove(&hash);
            }
        }
    }

    /// Get the number of cached entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if the cache is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Snapshot of mempool state for RPC queries.
///
/// Updated periodically by the runner from the mempool state.
#[derive(Debug, Clone, Default)]
pub struct MempoolSnapshot {
    /// Number of pending transactions (waiting to be included in a block).
    pub pending_count: usize,
    /// Number of transactions currently being executed (holding locks).
    pub executing_count: usize,
    /// Total number of transactions in the mempool.
    pub total_count: usize,
    /// Number of transactions blocked waiting for a winner.
    pub blocked_count: usize,
    /// When this snapshot was taken.
    pub updated_at: Option<Instant>,
}

/// Mutable node status state updated by the runner.
#[derive(Debug, Clone, Default)]
pub struct NodeStatusState {
    pub validator_id: u64,
    pub shard: u64,
    pub num_shards: u64,
    pub block_height: u64,
    pub view: u64,
    pub connected_peers: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// Health & Readiness Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /health` - liveness probe.
pub async fn health_handler() -> impl IntoResponse {
    Json(HealthResponse::default())
}

/// Handler for `GET /ready` - readiness probe.
pub async fn ready_handler(State(state): State<RpcState>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) {
        (
            StatusCode::OK,
            Json(ReadyResponse {
                status: "ready".to_string(),
                ready: true,
            }),
        )
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadyResponse {
                status: "not_ready".to_string(),
                ready: false,
            }),
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Metrics Handler
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /metrics` - Prometheus metrics.
pub async fn metrics_handler() -> impl IntoResponse {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();

    let mut buffer = Vec::new();
    if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
        tracing::error!(error = ?e, "Failed to encode metrics");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to encode metrics".to_string(),
        )
            .into_response();
    }

    (
        [(
            axum::http::header::CONTENT_TYPE,
            encoder.format_type().to_string(),
        )],
        buffer,
    )
        .into_response()
}

// ═══════════════════════════════════════════════════════════════════════════
// Status Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/status` - node status.
pub async fn status_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let node_status = state.node_status.read().await;
    let uptime = state.start_time.elapsed().as_secs();

    Json(NodeStatusResponse {
        validator_id: node_status.validator_id,
        shard: node_status.shard,
        num_shards: node_status.num_shards,
        block_height: node_status.block_height,
        view: node_status.view,
        connected_peers: node_status.connected_peers,
        uptime_secs: uptime,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// Handler for `GET /api/v1/sync` - sync status.
pub async fn sync_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let sync_status = state.sync_status.read().await;

    Json(SyncStatusResponse {
        state: format!("{:?}", sync_status.state).to_lowercase(),
        current_height: sync_status.current_height,
        target_height: sync_status.target_height,
        blocks_behind: sync_status.blocks_behind,
        sync_peers: sync_status.sync_peers,
        pending_fetches: sync_status.pending_fetches,
        queued_heights: sync_status.queued_heights,
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// Transaction Handlers
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `POST /api/v1/transactions` - submit transaction.
pub async fn submit_transaction_handler(
    State(state): State<RpcState>,
    Json(request): Json<SubmitTransactionRequest>,
) -> impl IntoResponse {
    // Decode hex
    let tx_bytes = match hex::decode(&request.transaction_hex) {
        Ok(bytes) => bytes,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!("Invalid hex encoding: {}", e)),
                }),
            );
        }
    };

    // Decode SBOR
    let transaction: RoutableTransaction = match sbor::prelude::basic_decode(&tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(SubmitTransactionResponse {
                    accepted: false,
                    hash: String::new(),
                    error: Some(format!("Invalid transaction format: {:?}", e)),
                }),
            );
        }
    };

    let hash = hex::encode(transaction.hash().as_bytes());

    // Send to node
    match state.tx_sender.try_send(transaction) {
        Ok(()) => (
            StatusCode::ACCEPTED,
            Json(SubmitTransactionResponse {
                accepted: true,
                hash,
                error: None,
            }),
        ),
        Err(mpsc::error::TrySendError::Full(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash,
                error: Some("Transaction queue full, try again later".to_string()),
            }),
        ),
        Err(mpsc::error::TrySendError::Closed(_)) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(SubmitTransactionResponse {
                accepted: false,
                hash,
                error: Some("Node is shutting down".to_string()),
            }),
        ),
    }
}

/// Handler for `GET /api/v1/transactions/:hash` - get transaction status.
pub async fn get_transaction_handler(
    State(state): State<RpcState>,
    Path(hash_hex): Path<String>,
) -> impl IntoResponse {
    // Parse the hash from hex (expects the raw hash bytes, not data to hash)
    let tx_hash = match Hash::from_hex(&hash_hex) {
        Ok(hash) => hash,
        Err(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: "error".to_string(),
                    committed_height: None,
                    decision: None,
                    blocked_by: None,
                    retry_tx: None,
                    error: Some("Invalid transaction hash: must be 64 hex characters".to_string()),
                }),
            );
        }
    };

    // Look up in cache
    let cache = state.tx_status_cache.read().await;
    match cache.get(&tx_hash) {
        Some(cached) => {
            let (status_str, committed_height, decision, blocked_by, retry_tx) =
                format_transaction_status(&cached.status);

            (
                StatusCode::OK,
                Json(TransactionStatusResponse {
                    hash: hash_hex,
                    status: status_str,
                    committed_height,
                    decision,
                    blocked_by,
                    retry_tx,
                    error: None,
                }),
            )
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(TransactionStatusResponse {
                hash: hash_hex,
                status: "unknown".to_string(),
                committed_height: None,
                decision: None,
                blocked_by: None,
                retry_tx: None,
                error: Some("Transaction not found in cache".to_string()),
            }),
        ),
    }
}

/// Format a TransactionStatus into RPC response fields.
fn format_transaction_status(
    status: &TransactionStatus,
) -> (
    String,
    Option<u64>,
    Option<String>,
    Option<String>,
    Option<String>,
) {
    match status {
        TransactionStatus::Pending => ("pending".to_string(), None, None, None, None),
        TransactionStatus::Committed(height) => {
            ("committed".to_string(), Some(height.0), None, None, None)
        }
        TransactionStatus::Executed(decision) => {
            let decision_str = match decision {
                TransactionDecision::Accept => "accept",
                TransactionDecision::Reject => "reject",
            };
            (
                "executed".to_string(),
                None,
                Some(decision_str.to_string()),
                None,
                None,
            )
        }
        TransactionStatus::Completed => ("completed".to_string(), None, None, None, None),
        TransactionStatus::Blocked { by } => (
            "blocked".to_string(),
            None,
            None,
            Some(hex::encode(by.as_bytes())),
            None,
        ),
        TransactionStatus::Retried { new_tx } => (
            "retried".to_string(),
            None,
            None,
            None,
            Some(hex::encode(new_tx.as_bytes())),
        ),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Mempool Handler
// ═══════════════════════════════════════════════════════════════════════════

/// Handler for `GET /api/v1/mempool` - mempool status.
pub async fn mempool_handler(State(state): State<RpcState>) -> impl IntoResponse {
    let snapshot = state.mempool_snapshot.read().await;
    Json(MempoolStatusResponse {
        pending_count: snapshot.pending_count,
        executing_count: snapshot.executing_count,
        total_count: snapshot.total_count,
        blocked_count: snapshot.blocked_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, Router};
    use hyperscale_types::BlockHeight;
    use tower::ServiceExt;

    fn create_test_state() -> RpcState {
        let (tx_sender, _rx) = mpsc::channel(100);
        RpcState {
            ready: Arc::new(AtomicBool::new(false)),
            sync_status: Arc::new(RwLock::new(SyncStatus::default())),
            node_status: Arc::new(RwLock::new(NodeStatusState::default())),
            tx_sender,
            start_time: Instant::now(),
            tx_status_cache: Arc::new(RwLock::new(TransactionStatusCache::new())),
            mempool_snapshot: Arc::new(RwLock::new(MempoolSnapshot::default())),
        }
    }

    #[tokio::test]
    async fn test_health_handler() {
        let app = Router::new()
            .route("/health", axum::routing::get(health_handler))
            .with_state(create_test_state());

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_ready_handler_not_ready() {
        let state = create_test_state();
        let app = Router::new()
            .route("/ready", axum::routing::get(ready_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn test_ready_handler_ready() {
        let state = create_test_state();
        state.ready.store(true, Ordering::SeqCst);
        let app = Router::new()
            .route("/ready", axum::routing::get(ready_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/ready")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // TransactionStatusCache Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_cache_new() {
        let cache = TransactionStatusCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn test_cache_update_and_get() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[1u8; 32]);

        cache.update(tx_hash, TransactionStatus::Pending);
        assert_eq!(cache.len(), 1);

        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Pending));
    }

    #[test]
    fn test_cache_status_transitions() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[2u8; 32]);

        // Pending -> Committed
        cache.update(tx_hash, TransactionStatus::Pending);
        cache.update(tx_hash, TransactionStatus::Committed(BlockHeight(10)));

        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Committed(h) if h.0 == 10));

        // Committed -> Executed
        cache.update(
            tx_hash,
            TransactionStatus::Executed(TransactionDecision::Accept),
        );
        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(
            cached.status,
            TransactionStatus::Executed(TransactionDecision::Accept)
        ));

        // Executed -> Completed
        cache.update(tx_hash, TransactionStatus::Completed);
        let cached = cache.get(&tx_hash).unwrap();
        assert!(matches!(cached.status, TransactionStatus::Completed));
    }

    #[test]
    fn test_cache_blocked_status() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[3u8; 32]);
        let blocker_hash = Hash::from_bytes(&[4u8; 32]);

        cache.update(tx_hash, TransactionStatus::Blocked { by: blocker_hash });

        let cached = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Blocked { by } = &cached.status {
            assert_eq!(*by, blocker_hash);
        } else {
            panic!("Expected Blocked status");
        }
    }

    #[test]
    fn test_cache_retried_status() {
        let mut cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[5u8; 32]);
        let retry_hash = Hash::from_bytes(&[6u8; 32]);

        cache.update(tx_hash, TransactionStatus::Retried { new_tx: retry_hash });

        let cached = cache.get(&tx_hash).unwrap();
        if let TransactionStatus::Retried { new_tx } = &cached.status {
            assert_eq!(*new_tx, retry_hash);
        } else {
            panic!("Expected Retried status");
        }
    }

    #[test]
    fn test_cache_get_unknown() {
        let cache = TransactionStatusCache::new();
        let tx_hash = Hash::from_bytes(&[7u8; 32]);
        assert!(cache.get(&tx_hash).is_none());
    }

    #[test]
    fn test_cache_with_config() {
        let cache = TransactionStatusCache::with_config(10, Duration::from_secs(60));
        assert!(cache.is_empty());
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // format_transaction_status Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[test]
    fn test_format_pending() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Pending);
        assert_eq!(status, "pending");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_committed() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Committed(BlockHeight(42)));
        assert_eq!(status, "committed");
        assert_eq!(height, Some(42));
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_executed_accept() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Executed(TransactionDecision::Accept));
        assert_eq!(status, "executed");
        assert!(height.is_none());
        assert_eq!(decision, Some("accept".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_executed_reject() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Executed(TransactionDecision::Reject));
        assert_eq!(status, "executed");
        assert!(height.is_none());
        assert_eq!(decision, Some("reject".to_string()));
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_completed() {
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Completed);
        assert_eq!(status, "completed");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_blocked() {
        let blocker = Hash::from_bytes(&[0xab; 32]);
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Blocked { by: blocker });
        assert_eq!(status, "blocked");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert_eq!(blocked_by, Some(hex::encode(blocker.as_bytes())));
        assert!(retry_tx.is_none());
    }

    #[test]
    fn test_format_retried() {
        let new_tx = Hash::from_bytes(&[0xcd; 32]);
        let (status, height, decision, blocked_by, retry_tx) =
            format_transaction_status(&TransactionStatus::Retried { new_tx });
        assert_eq!(status, "retried");
        assert!(height.is_none());
        assert!(decision.is_none());
        assert!(blocked_by.is_none());
        assert_eq!(retry_tx, Some(hex::encode(new_tx.as_bytes())));
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Transaction Status Handler Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_get_transaction_not_found() {
        let state = create_test_state();
        let app = Router::new()
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
            .with_state(state);

        let tx_hash = hex::encode([0u8; 32]);
        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", tx_hash))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_get_transaction_invalid_hex() {
        let state = create_test_state();
        let app = Router::new()
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/tx/not_valid_hex!")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_get_transaction_found() {
        let state = create_test_state();
        // Create a hash from some input bytes
        let tx_hash = Hash::from_bytes(&[0x12; 32]);
        let tx_hash_hex = hex::encode(tx_hash.as_bytes());

        // Insert a transaction into the cache
        {
            let mut cache = state.tx_status_cache.write().await;
            cache.update(tx_hash, TransactionStatus::Pending);
        }

        let app = Router::new()
            .route("/tx/{hash}", axum::routing::get(get_transaction_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri(format!("/tx/{}", tx_hash_hex))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response and verify status
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let resp: TransactionStatusResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(resp.status, "pending");
        assert_eq!(resp.hash, tx_hash_hex);
    }

    // ═══════════════════════════════════════════════════════════════════════════
    // Mempool Handler Tests
    // ═══════════════════════════════════════════════════════════════════════════

    #[tokio::test]
    async fn test_mempool_handler_default() {
        let state = create_test_state();
        let app = Router::new()
            .route("/mempool", axum::routing::get(mempool_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_mempool_handler_with_data() {
        let state = create_test_state();

        // Update the mempool snapshot
        {
            let mut snapshot = state.mempool_snapshot.write().await;
            snapshot.pending_count = 10;
            snapshot.executing_count = 5;
            snapshot.blocked_count = 2;
            snapshot.total_count = 17;
        }

        let app = Router::new()
            .route("/mempool", axum::routing::get(mempool_handler))
            .with_state(state);

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/mempool")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        // Parse response body
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let resp: MempoolStatusResponse = serde_json::from_slice(&body).unwrap();

        assert_eq!(resp.pending_count, 10);
        assert_eq!(resp.executing_count, 5);
        assert_eq!(resp.blocked_count, 2);
        assert_eq!(resp.total_count, 17);
    }
}
