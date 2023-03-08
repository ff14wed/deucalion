use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{format_err, Error, Result};

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
        }
    }

    fn claim_id(&mut self) -> usize {
        let original = self.counter;
        self.counter += 1;
        return original;
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

/// Handle the client message and send a success/failure esponse back
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
    match payload_handler(payload) {
        Ok(()) => {
            peer.frames
                .send(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx,
                    data: String::from("OK").into_bytes(),
                })
                .await?
        }
        Err(e) => {
            peer.frames
                .send(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx,
                    data: String::from(e.to_string()).into_bytes(),
                })
                .await?
        }
    }
    Ok(())
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

    frames
        .send(
            rpc::Payload {
                op: rpc::MessageOps::Debug,
                ctx: 9000,
                data: String::from("SERVER HELLO").into_bytes(),
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
                    _ => {
                        handle_client_message(payload, &mut peer, &payload_handler).await?;
                    }
                }
            }

            // A message was received from the broadcast.
            Ok(Message::Data(payload)) => {
                peer.frames.send(payload).await?;
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
                        error!("error occurred processing stream = {:?}", e);
                    }
                });
            }
            Err(e) => return Err(format_err!("Unable to connect to client: {}", e)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ntest::timeout;
    use rand::Rng;
    use winapi::um::processthreadsapi;

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn named_pipe_load_test() {
        let (signal_tx, signal_rx) = mpsc::channel(1);
        let state = Arc::new(Mutex::new(Shared::new(signal_tx)));
        let state_clone = state.clone();

        let pid = unsafe { processthreadsapi::GetCurrentProcessId() };
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", pid);
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

        // Create a frame decoder that processes the client stream
        let codec = rpc::PayloadCodec::new();
        let frames = Framed::new(client, codec);
        // This state isn't really used for anything
        let (dummy_signal_tx, _) = mpsc::channel(1);
        let dummy_state = Arc::new(Mutex::new(Shared::new(dummy_signal_tx)));
        let mut peer = Peer::new(dummy_state, frames).await.unwrap();

        // Handle the SERVER_HELLO message
        let peer_message = peer.next().await.unwrap();
        if let Ok(Message::Request(payload)) = peer_message {
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
        while let Some(result) = peer.next().await {
            match result {
                // A request was received from the current user
                Ok(Message::Request(payload)) => {
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
