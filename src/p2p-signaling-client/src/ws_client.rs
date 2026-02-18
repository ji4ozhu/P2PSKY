use futures_util::{SinkExt, StreamExt};
use p2p_signaling_proto::{
    ErrorPayload, RegisterPayload, SignalingMessage, PROTOCOL_VERSION,
};
use std::time::Duration;
use thiserror::Error;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing;

#[derive(Error, Debug)]
pub enum SignalingClientError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Connection closed")]
    Closed,
    #[error("Not connected")]
    NotConnected,
    #[error("Server error {code}: {message}")]
    ServerError { code: u32, message: String },
    #[error("Operation timed out")]
    Timeout,
}

/// Cloneable sender half of the signaling client.
/// Use this to send messages after splitting the client.
#[derive(Clone)]
pub struct SignalingSender {
    tx: mpsc::UnboundedSender<SignalingMessage>,
}

impl SignalingSender {
    pub fn send(&self, msg: SignalingMessage) -> Result<(), SignalingClientError> {
        self.tx.send(msg).map_err(|_| SignalingClientError::Closed)
    }
}

/// WebSocket-based signaling client for exchanging ICE candidates
/// and coordinating P2P connections.
pub struct SignalingClient {
    /// Channel to send messages to the WebSocket writer task.
    outgoing_tx: Option<mpsc::UnboundedSender<SignalingMessage>>,
    /// Channel to receive messages from the WebSocket reader task.
    incoming_rx: Option<mpsc::UnboundedReceiver<SignalingMessage>>,
    /// Our registered peer ID.
    peer_id: Option<String>,
    /// H7: Handle to the WebSocket I/O task so it can be aborted on drop.
    io_task: Option<JoinHandle<()>>,
}

impl SignalingClient {
    /// Connect to the signaling server at the given WebSocket URL.
    pub async fn connect(url: &str) -> Result<Self, SignalingClientError> {
        let (ws_stream, _response) = connect_async(url).await?;
        let (mut ws_write, mut ws_read) = ws_stream.split();

        let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<SignalingMessage>();
        let (incoming_tx, incoming_rx) = mpsc::unbounded_channel::<SignalingMessage>();

        // Combined I/O task: handles reading, writing, WebSocket Ping/Pong,
        // and application-level heartbeat in a single select! loop.
        let io_task = tokio::spawn(async move {
            let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
            heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            // Skip the first immediate tick
            heartbeat.tick().await;

            loop {
                tokio::select! {
                    // Incoming WebSocket messages
                    msg = ws_read.next() => {
                        match msg {
                            Some(Ok(Message::Text(text))) => {
                                match serde_json::from_str::<SignalingMessage>(&text) {
                                    Ok(msg) => {
                                        if incoming_tx.send(msg).is_err() {
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to parse signaling message: {}", e
                                        );
                                    }
                                }
                            }
                            Some(Ok(Message::Ping(data))) => {
                                // Respond to WebSocket-level Ping with Pong
                                if ws_write.send(Message::Pong(data)).await.is_err() {
                                    tracing::warn!("Failed to send WebSocket Pong");
                                    break;
                                }
                            }
                            Some(Ok(Message::Close(_))) => {
                                tracing::info!("WebSocket closed by server");
                                break;
                            }
                            Some(Ok(_)) => {} // Ignore binary, pong, etc.
                            Some(Err(e)) => {
                                tracing::error!("WebSocket read error: {}", e);
                                break;
                            }
                            None => {
                                tracing::info!("WebSocket stream ended");
                                break;
                            }
                        }
                    }
                    // Outgoing signaling messages from the application
                    msg = outgoing_rx.recv() => {
                        match msg {
                            Some(msg) => {
                                match serde_json::to_string(&msg) {
                                    Ok(json) => {
                                        if ws_write.send(Message::Text(json.into())).await.is_err() {
                                            tracing::warn!("WebSocket write failed, closing");
                                            break;
                                        }
                                    }
                                    Err(e) => {
                                        tracing::error!(
                                            "Failed to serialize signaling message: {}", e
                                        );
                                    }
                                }
                            }
                            None => {
                                // outgoing channel closed — client dropped
                                break;
                            }
                        }
                    }
                    // Periodic heartbeat to keep the connection alive.
                    // The Go server has a 60s read deadline; this 25s interval
                    // ensures the deadline is always refreshed.
                    _ = heartbeat.tick() => {
                        let ping_json = serde_json::to_string(&SignalingMessage::Ping)
                            .unwrap_or_default();
                        if ws_write.send(Message::Text(ping_json.into())).await.is_err() {
                            tracing::warn!("Failed to send heartbeat ping");
                            break;
                        }
                        tracing::trace!("Sent heartbeat Ping");
                    }
                }
            }
            tracing::warn!("Signaling WebSocket I/O task exiting");
        });

        Ok(Self {
            outgoing_tx: Some(outgoing_tx),
            incoming_rx: Some(incoming_rx),
            peer_id: None,
            io_task: Some(io_task),
        })
    }

    /// Register with the signaling server using the given peer ID.
    /// H8: Times out after 10 seconds if the server doesn't respond.
    pub async fn register(&mut self, peer_id: &str) -> Result<(), SignalingClientError> {
        let msg = SignalingMessage::Register(RegisterPayload {
            peer_id: peer_id.to_string(),
            protocol_version: PROTOCOL_VERSION,
        });
        self.send(msg)?;

        // Wait for Registered or Error response with timeout
        let register_fut = async {
            loop {
                let response = self.recv().await?;
                match response {
                    SignalingMessage::Registered(payload) => {
                        tracing::info!("Registered as peer '{}'", payload.peer_id);
                        self.peer_id = Some(payload.peer_id);
                        return Ok(());
                    }
                    SignalingMessage::Error(ErrorPayload { code, message }) => {
                        return Err(SignalingClientError::ServerError { code, message });
                    }
                    _ => {
                        // Ignore unexpected messages during registration
                        continue;
                    }
                }
            }
        };

        tokio::time::timeout(Duration::from_secs(10), register_fut)
            .await
            .map_err(|_| {
                tracing::error!("Registration timed out after 10s");
                SignalingClientError::Timeout
            })?
    }

    /// Send a signaling message.
    pub fn send(&self, msg: SignalingMessage) -> Result<(), SignalingClientError> {
        self.outgoing_tx
            .as_ref()
            .ok_or(SignalingClientError::Closed)?
            .send(msg)
            .map_err(|_| SignalingClientError::Closed)
    }

    /// Receive the next signaling message.
    pub async fn recv(&mut self) -> Result<SignalingMessage, SignalingClientError> {
        self.incoming_rx
            .as_mut()
            .ok_or(SignalingClientError::Closed)?
            .recv()
            .await
            .ok_or(SignalingClientError::Closed)
    }

    /// Get our registered peer ID.
    pub fn peer_id(&self) -> Option<&str> {
        self.peer_id.as_deref()
    }

    /// Send a ping heartbeat.
    pub fn send_ping(&self) -> Result<(), SignalingClientError> {
        self.send(SignalingMessage::Ping)
    }

    /// Split the client into a cloneable sender, the message receiver,
    /// and the I/O task handle.
    /// This consumes the client. Use after registration is complete.
    pub fn into_parts(
        mut self,
    ) -> (
        SignalingSender,
        mpsc::UnboundedReceiver<SignalingMessage>,
        Option<JoinHandle<()>>,
    ) {
        let tx = self.outgoing_tx.take().expect("outgoing_tx already taken");
        let rx = self.incoming_rx.take().expect("incoming_rx already taken");
        (
            SignalingSender { tx },
            rx,
            self.io_task.take(),
        )
    }
}

/// H7: Abort the WebSocket I/O task when the client is dropped to prevent
/// goroutine-like leaks where the task hangs forever on a stuck read/write.
impl Drop for SignalingClient {
    fn drop(&mut self) {
        if let Some(h) = self.io_task.take() {
            h.abort();
        }
    }
}
