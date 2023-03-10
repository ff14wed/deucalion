use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Error, Result};

use futures::{SinkExt, Stream, StreamExt};

use crate::namedpipe::Endpoint;
use tokio::sync::{mpsc, Mutex};
use tokio_util::codec::Framed;

use tokio::io::{AsyncRead, AsyncWrite};

use stream_cancel::Tripwire;

use log::{error, info};

use crate::rpc;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<rpc::Payload>;

/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<rpc::Payload>;

/// Data that is shared between all peers in the server.
///
/// This is the set of `Tx` handles for all connected clients. Messages are
/// broadcasted to all peers by iterating over the `peers` entries and sending a
/// copy of the message on each `Tx`.
pub struct Shared {
    peers: HashMap<usize, Tx>,
    counter: usize,
    signal: mpsc::Sender<()>,

    recv_initialized: bool,
    send_initialized: bool,
}

/// The state for each connected client.
struct Peer<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    id: usize,
    /// The connection wrapped with the `PayloadCodec`.
    ///
    /// This handles sending and receiving data on the socket. With this codec,
    /// we can work at the Payload level instead of having to manage the
    /// raw byte operations.
    frames: Framed<T, rpc::PayloadCodec>,

    /// Receive half of the message channel.
    ///
    /// This is used to receive messages from broadcasts.
    rx: Rx,
}

impl Shared {
    pub fn new(signal: mpsc::Sender<()>) -> Self {
        Shared {
            peers: HashMap::new(),
            counter: 0,
            signal,

            recv_initialized: false,
            send_initialized: false,
        }
    }

    fn claim_id(&mut self) -> usize {
        let original = self.counter;
        self.counter += 1;
        return original;
    }

    pub fn set_recv_state(&mut self, initialized: bool) {
        self.recv_initialized = initialized;
    }

    pub fn set_send_state(&mut self, initialized: bool) {
        self.send_initialized = initialized;
    }

    pub async fn shutdown(&self) {
        let signal_tx = self.signal.clone();
        let _ = signal_tx.send(()).await;
    }

    pub async fn broadcast(&mut self, message: rpc::Payload) {
        for peer in self.peers.iter_mut() {
            let _ = peer.1.send(message.clone());
        }
    }
}

impl<T> Peer<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    async fn new(
        state: Arc<Mutex<Shared>>,
        frames: Framed<T, rpc::PayloadCodec>,
    ) -> tokio::io::Result<Peer<T>> {
        let (tx, rx) = mpsc::unbounded_channel();

        // Add an entry for this `Peer` in the shared state map.
        let mut state = state.lock().await;
        let id = state.claim_id();
        state.peers.insert(id, tx);

        Ok(Peer { id, frames, rx })
    }
}

#[derive(Debug)]
enum Message {
    /// A message that was sent from a client to the server
    Request(rpc::Payload),

    /// A message that should be sent to clients
    Data(rpc::Payload),
}

/// Peer implements `Stream` in a way that polls both the `Rx`, and `Framed` types.
/// A message is produced whenever an event is ready until the `Framed` stream returns `None`.
impl<T> Stream for Peer<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    type Item = Result<Message, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First poll the `UnboundedReceiver`.
        if let Poll::Ready(Some(v)) = Pin::new(&mut self.rx).poll_recv(cx) {
            return Poll::Ready(Some(Ok(Message::Data(v))));
        }

        // Secondly poll the `Framed` stream.
        let result: Option<_> = futures::ready!(Pin::new(&mut self.frames).poll_next(cx));

        Poll::Ready(match result {
            // We've received a request
            Some(Ok(message)) => Some(Ok(Message::Request(message))),

            // An error occured.
            Some(Err(e)) => Some(Err(e.into())),

            // The stream has been exhausted.
            None => None,
        })
    }
}

#[repr(u32)]
enum BroadcastFilter {
    AllowLobbyRecv = 1,
    AllowZoneRecv = 1 << 1,
    AllowChatRecv = 1 << 2,
    AllowLobbySend = 1 << 3,
    AllowZoneSend = 1 << 4,
    AllowChatSend = 1 << 5,
    AllowOther = 1 << 6, // In case the channel is not one of [Lobby, Zone, Chat]
}

fn allow_broadcast(op: rpc::MessageOps, channel: u32, filter: u32) -> bool {
    match op {
        rpc::MessageOps::Recv => match channel {
            0 => (filter & BroadcastFilter::AllowLobbyRecv as u32) > 0,
            1 => (filter & BroadcastFilter::AllowZoneRecv as u32) > 0,
            2 => (filter & BroadcastFilter::AllowChatRecv as u32) > 0,
            _ => (filter & BroadcastFilter::AllowOther as u32) > 0,
        },
        rpc::MessageOps::Send => match channel {
            0 => (filter & BroadcastFilter::AllowLobbySend as u32) > 0,
            1 => (filter & BroadcastFilter::AllowZoneSend as u32) > 0,
            2 => (filter & BroadcastFilter::AllowChatSend as u32) > 0,
            _ => (filter & BroadcastFilter::AllowOther as u32) > 0,
        },
        // All other message ops are always allowed
        _ => true,
    }
}

/// Handle the client message and send a success/failure response back
async fn handle_client_message<T, F>(
    payload: rpc::Payload,
    peer: &mut Peer<T>,
    payload_handler: &F,
) -> Result<(), Error>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
    F: Fn(rpc::Payload) -> Result<(), Error>,
{
    let ctx = payload.ctx;

    let ack_prefix = {
        match payload.op {
            rpc::MessageOps::Recv => "RECV ",
            rpc::MessageOps::Send => "SEND ",
            _ => "",
        }
    };

    match payload_handler(payload) {
        Ok(()) => {
            peer.frames
                .send(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx,
                    data: format!("{}OK", ack_prefix).into_bytes(),
                })
                .await?
        }
        Err(e) => {
            peer.frames
                .send(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx,
                    data: format!("{}{}", ack_prefix, e).into_bytes(),
                })
                .await?
        }
    }
    Ok(())
}

async fn server_hello_string(state: Arc<Mutex<Shared>>) -> String {
    let state = state.lock().await;
    let recv_status = if state.recv_initialized {
        "RECV INITIALIZED."
    } else {
        "RECV REQUIRES SIG."
    };
    let send_status = if state.send_initialized {
        "SEND INITIALIZED."
    } else {
        "SEND REQUIRES SIG."
    };
    format!("SERVER HELLO. STATUS: {} {}", recv_status, send_status)
}

/// Process an individual client
async fn process<F>(
    state: Arc<Mutex<Shared>>,
    stream: impl AsyncRead + AsyncWrite + std::marker::Unpin,
    payload_handler: F,
) -> Result<(), Error>
where
    F: Fn(rpc::Payload) -> Result<(), Error>,
{
    let codec = rpc::PayloadCodec::new();
    let mut frames = Framed::new(stream, codec);

    let hello_string = server_hello_string(state.clone()).await;

    frames
        .send(
            rpc::Payload {
                op: rpc::MessageOps::Debug,
                ctx: 9000,
                data: hello_string.into_bytes(),
            }
            .into(),
        )
        .await?;

    // Register our peer with state
    let mut peer = Peer::new(state.clone(), frames).await?;

    info!("New client connected: {}", peer.id);

    let ping_payload = rpc::Payload {
        op: rpc::MessageOps::Ping,
        ctx: 0,
        data: Vec::new(),
    };

    // Default packet filter is AllowZoneRecv only
    let mut filter: u32 = BroadcastFilter::AllowZoneRecv as u32;

    // Process incoming messages until our stream is exhausted by a disconnect.
    while let Some(result) = peer.next().await {
        match result {
            // A request was received from the current user
            Ok(Message::Request(payload)) => {
                let state = state.lock().await;

                match payload.op {
                    rpc::MessageOps::Ping => {
                        peer.frames.send(ping_payload.clone()).await?;
                    }
                    rpc::MessageOps::Exit => {
                        state.shutdown().await;
                        return Ok(());
                    }
                    rpc::MessageOps::Option => {
                        filter = payload.ctx;
                        peer.frames
                            .send(rpc::Payload {
                                op: rpc::MessageOps::Debug,
                                ctx: 0,
                                data: format!("Packet filters set: {filter:#010b}").into_bytes(),
                            })
                            .await?
                    }
                    _ => {
                        handle_client_message(payload, &mut peer, &payload_handler).await?;
                    }
                }
            }

            // A message was received from the broadcast.
            Ok(Message::Data(payload)) => {
                if allow_broadcast(payload.op, payload.ctx, filter) {
                    peer.frames.send(payload).await?;
                }
            }
            Err(e) => {
                error!(
                    "an error occured while processing messages for peer {}; error = {:?}",
                    peer.id, e
                );
            }
        }
    }

    // If this section is reached it means that the client was disconnected!
    {
        info!("client disconnected: {}", peer.id);
        let mut state = state.lock().await;
        state.peers.remove(&peer.id);
        // Exit once all clients are disconnected
        if state.peers.len() == 0 {
            state.shutdown().await;
        }
    }

    Ok(())
}

pub async fn run<F>(
    pipe_name: String,
    state: Arc<Mutex<Shared>>,
    mut signal_rx: mpsc::Receiver<()>,
    payload_handler: F,
) -> Result<(), Error>
where
    F: Fn(rpc::Payload) -> Result<(), Error> + Sync + Send + Clone + 'static,
{
    let (trigger, tripwire) = Tripwire::new();

    let endpoint = Endpoint::new(pipe_name);

    let incoming = endpoint.incoming()?.take_until(tripwire);

    futures::pin_mut!(incoming);

    tokio::spawn(async move {
        let _ = signal_rx.recv().await;
        info!("Shutdown signal received");
        trigger.cancel();
    });

    // Create a new process loop task for each client
    while let Some(result) = incoming.next().await {
        match result {
            Ok(stream) => {
                let state = state.clone();
                let handler = payload_handler.clone();
                tokio::spawn(async move {
                    if let Err(e) = process(state, stream, handler).await {
                        error!("Error occurred when processing stream = {:?}", e);
                    }
                });
            }
            Err(e) => error!("Unable to connect to client: {}", e),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntest::timeout;
    use rand::Rng;
    use tokio::select;

    #[test]
    fn test_individual_packet_filters() {
        let configurations = [
            (BroadcastFilter::AllowLobbyRecv, rpc::MessageOps::Recv, 0),
            (BroadcastFilter::AllowZoneRecv, rpc::MessageOps::Recv, 1),
            (BroadcastFilter::AllowChatRecv, rpc::MessageOps::Recv, 2),
            (BroadcastFilter::AllowLobbySend, rpc::MessageOps::Send, 0),
            (BroadcastFilter::AllowZoneSend, rpc::MessageOps::Send, 1),
            (BroadcastFilter::AllowChatSend, rpc::MessageOps::Send, 2),
            (BroadcastFilter::AllowOther, rpc::MessageOps::Recv, 100),
        ];
        const ALLOW_EVERYTHING: u32 = 0xFF;
        for (filter, op, ctx) in configurations {
            let filter = filter as u32;
            assert_eq!(allow_broadcast(op, ctx, ALLOW_EVERYTHING), true);
            assert_eq!(allow_broadcast(op, ctx, filter), true);
            assert_eq!(allow_broadcast(op, ctx, ALLOW_EVERYTHING & !filter), false);
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_server_hello_message() {
        let (signal_tx, _) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(Shared::new(signal_tx)));

        let combinations = vec![
            (
                false,
                false,
                "SERVER HELLO. STATUS: RECV REQUIRES SIG. SEND REQUIRES SIG.",
            ),
            (
                false,
                true,
                "SERVER HELLO. STATUS: RECV REQUIRES SIG. SEND INITIALIZED.",
            ),
            (
                true,
                false,
                "SERVER HELLO. STATUS: RECV INITIALIZED. SEND REQUIRES SIG.",
            ),
            (
                true,
                true,
                "SERVER HELLO. STATUS: RECV INITIALIZED. SEND INITIALIZED.",
            ),
        ];

        for (recv_initialized, send_initialized, expected_hello) in combinations {
            let state_clone = state.clone();
            {
                let mut state = state_clone.lock().await;
                state.set_recv_state(recv_initialized);
                state.set_send_state(send_initialized);
            }

            assert_eq!(
                server_hello_string(state_clone).await,
                expected_hello.to_string()
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_combined_broadcast_filters() {
        let (signal_tx, signal_rx) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(Shared::new(signal_tx)));
        let state_clone = state.clone();

        let test_id: u16 = rand::thread_rng().gen();
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", test_id);
        let pipe_name_clone = pipe_name.clone();

        tokio::spawn(async move {
            if let Err(e) = run(pipe_name_clone, state, signal_rx, move |_: rpc::Payload| {
                Ok(())
            })
            .await
            {
                panic!("Server should not fail to run: {:?}", e);
            }
        });

        // Give the server some time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect client to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(client, codec);

        // Handle the SERVER_HELLO message
        let peer_message = frames.next().await.unwrap();
        if let Ok(payload) = peer_message {
            assert_eq!(payload.ctx, 9000);
        } else {
            panic!("Did not properly receive Server Hello");
        }

        let filter = BroadcastFilter::AllowChatRecv as u32
            | BroadcastFilter::AllowChatSend as u32
            | BroadcastFilter::AllowZoneRecv as u32;

        // Send option
        frames
            .send(rpc::Payload {
                op: rpc::MessageOps::Option,
                ctx: filter,
                data: Vec::new(),
            })
            .await
            .unwrap();

        let peer_message = frames.next().await.unwrap();
        if let Ok(payload) = peer_message {
            assert_eq!(payload.op, rpc::MessageOps::Debug);
            assert_eq!(
                String::from_utf8(payload.data).unwrap(),
                "Packet filters set: 0b00100110",
            );
        } else {
            panic!("Did not properly receive Server Hello");
        }

        let configurations = vec![
            (rpc::MessageOps::Recv, 0, false),
            (rpc::MessageOps::Recv, 1, true),
            (rpc::MessageOps::Recv, 2, true),
            (rpc::MessageOps::Send, 0, false),
            (rpc::MessageOps::Send, 1, false),
            (rpc::MessageOps::Send, 2, true),
            (rpc::MessageOps::Recv, 100, false),
        ];

        for (op, ctx, should_be_allowed) in configurations {
            state_clone
                .lock()
                .await
                .broadcast(rpc::Payload {
                    op,
                    ctx,
                    data: Vec::new(),
                })
                .await;

            select! {
                payload = frames.next() => {
                    assert_eq!(should_be_allowed, true, "packet should be filtered: {:?}", payload)
                }
                _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                    assert_eq!(should_be_allowed, false, "packet should not be filtered: {:?}: {}", op, ctx)
                }
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_server_shutdown() {
        let (signal_tx, signal_rx) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(Shared::new(signal_tx)));

        let test_id: u16 = rand::thread_rng().gen();
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", test_id);
        let pipe_name_clone = pipe_name.clone();

        let server_task = tokio::spawn(async move {
            if let Err(e) = run(pipe_name_clone, state, signal_rx, move |_: rpc::Payload| {
                Ok(())
            })
            .await
            {
                panic!("Server should not fail to run: {:?}", e);
            }
        });

        // Give the server some time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect client to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(client, codec);

        // Handle the SERVER_HELLO message
        let peer_message = frames.next().await.unwrap();
        if let Ok(payload) = peer_message {
            assert_eq!(payload.ctx, 9000);
        } else {
            panic!("Did not properly receive Server Hello");
        }

        // Send exit
        frames
            .send(rpc::Payload {
                op: rpc::MessageOps::Exit,
                ctx: 0,
                data: Vec::new(),
            })
            .await
            .unwrap();

        // Wait on the server to shut down
        let _ = server_task.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn named_pipe_load_test() {
        let (signal_tx, signal_rx) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(Shared::new(signal_tx)));
        let state_clone = state.clone();

        let test_id: u16 = rand::thread_rng().gen();
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", test_id);
        let pipe_name_clone = pipe_name.clone();

        tokio::spawn(async move {
            if let Err(e) = run(pipe_name_clone, state, signal_rx, move |_: rpc::Payload| {
                Ok(())
            })
            .await
            {
                panic!("Server should not fail to run: {:?}", e);
            }
        });

        // Give the server some time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        let client = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect client to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(client, codec);

        // Handle the SERVER_HELLO message
        let peer_message = frames.next().await.unwrap();
        if let Ok(payload) = peer_message {
            assert_eq!(payload.ctx, 9000);
        } else {
            panic!("Did not properly receive Server Hello");
        }

        // Synchronously send many packets before the client can process them
        const NUM_PACKETS: u32 = 10000;
        for i in 0..NUM_PACKETS {
            let mut dummy_data = Vec::from([0u8; 5000]);
            rand::thread_rng().fill(&mut dummy_data[..]);

            state_clone
                .lock()
                .await
                .broadcast(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx: i,
                    data: dummy_data,
                })
                .await;
        }

        // Test that every packet was received in order
        let mut num_received = 0u32;
        while let Some(result) = frames.next().await {
            match result {
                // A request was received from the current user
                Ok(payload) => {
                    assert_eq!(
                        payload.ctx, num_received,
                        "Received data from pipe does not match expected index!"
                    );
                    num_received += 1;
                    if num_received >= NUM_PACKETS {
                        return;
                    }
                }
                _ => (),
            }
        }
    }
}
