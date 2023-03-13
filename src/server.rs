use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{format_err, Error, Result};

use futures::{SinkExt, Stream, StreamExt};

use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinSet;
use tokio_util::codec::Framed;

use once_cell::sync::OnceCell;

use stream_cancel::Tripwire;

use log::{error, info};

use crate::namedpipe::Endpoint;
use crate::rpc;

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<rpc::Payload>;

/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<rpc::Payload>;

#[derive(Debug)]
enum Message {
    /// A message that was sent from a subscriber to the server
    Request(rpc::Payload),

    /// A message that should be sent to subscribers
    Data(rpc::Payload),
}

/// The state for each connected subscriber.
struct Subscriber<T>
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

/// Subscriber implements `Stream` in a way that polls both the broadcast `Rx`
/// channel and the `Framed` channel for messages sent to the named pipe by
/// a subscriber.
/// A message is produced whenever an event is ready and yields `None` when
/// the subscriber connection is closed.
impl<T> Stream for Subscriber<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    type Item = Result<Message>;

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
        rpc::MessageOps::RecvOther => (filter & BroadcastFilter::AllowOther as u32) > 0,
        rpc::MessageOps::SendOther => (filter & BroadcastFilter::AllowOther as u32) > 0,
        // All other message ops are always allowed
        _ => true,
    }
}

/// Global state that the server keeps for all connected subscribers.
///
/// Messages are broadcasted to all subscribers by iterating over each `Tx`
/// entries and sending a copy of the message.
struct State {
    subscribers: HashMap<usize, Tx>,
    counter: usize,
    recv_hooked: bool,
    send_hooked: bool,
    send_lobby_hooked: bool,
}

impl State {
    fn claim_id(&mut self) -> usize {
        let original = self.counter;
        self.counter += 1;
        return original;
    }

    /// Adds a new subscriber to the server and returns the subscriber ID and a
    /// `Rx` that can be used to receive messages from broadcasts
    fn new_subscriber(&mut self) -> (usize, Rx) {
        let id = self.claim_id();
        let (tx, rx) = mpsc::unbounded_channel();
        self.subscribers.insert(id, tx);
        (id, rx)
    }

    fn hook_status_string(status: bool) -> &'static str {
        return if status { "ON" } else { "OFF" };
    }

    fn server_hello_string(&self) -> String {
        format!(
            "SERVER HELLO. HOOK STATUS: RECV {}. SEND {}. SEND_LOBBY {}.",
            Self::hook_status_string(self.recv_hooked),
            Self::hook_status_string(self.send_hooked),
            Self::hook_status_string(self.send_lobby_hooked),
        )
    }
}

#[derive(Clone)]
pub struct Server {
    state: Arc<Mutex<State>>,
    shutdown_tx: OnceCell<mpsc::Sender<()>>,
}

impl Server {
    pub fn new() -> Self {
        Server {
            state: Arc::new(Mutex::new(State {
                subscribers: HashMap::new(),
                counter: 0,
                recv_hooked: false,
                send_hooked: false,
                send_lobby_hooked: false,
            })),
            shutdown_tx: OnceCell::new(),
        }
    }

    /// Notifies the server of the hook status.
    pub async fn set_hook_status(&self, r: bool, s: bool, sl: bool) {
        let mut state = self.state.lock().await;
        state.recv_hooked = r;
        state.send_hooked = s;
        state.send_lobby_hooked = sl;
    }

    pub async fn shutdown(&self) {
        let _ = self
            .shutdown_tx
            .get()
            .expect("cannot shutdown before the server is run!")
            .send(())
            .await;
    }

    pub async fn broadcast(&self, message: rpc::Payload) {
        let mut state = self.state.lock().await;
        for subscriber in state.subscribers.iter_mut() {
            let _ = subscriber.1.send(message.clone());
        }
    }

    /// Handle the payload from subscriber and send a success/failure response back
    async fn handle_payload_from_subscriber<T, F>(
        payload: rpc::Payload,
        subscriber: &mut Subscriber<T>,
        payload_handler: &F,
    ) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
        F: Fn(rpc::Payload) -> Result<()>,
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
                subscriber
                    .frames
                    .send(rpc::Payload {
                        op: rpc::MessageOps::Debug,
                        ctx,
                        data: format!("{}OK", ack_prefix).into_bytes(),
                    })
                    .await?
            }
            Err(e) => {
                subscriber
                    .frames
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

    /// Subscriber message loop. Returns an error if it has trouble writing
    /// to the connection.
    /// Returns true if it returned because of an Exit request. Returns false
    /// if the connection was closed naturally.
    async fn subscriber_msg_loop<T, F>(
        &self,
        mut subscriber: &mut Subscriber<T>,
        payload_handler: F,
    ) -> Result<bool>
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
        F: Fn(rpc::Payload) -> Result<()>,
    {
        let ping_payload = rpc::Payload {
            op: rpc::MessageOps::Ping,
            ctx: 0,
            data: Vec::new(),
        };

        // Default packet filter is AllowZoneRecv only
        let mut filter: u32 = BroadcastFilter::AllowZoneRecv as u32;

        // Process incoming messages until our stream is exhausted by a disconnect.
        while let Some(result) = subscriber.next().await {
            match result {
                // A request was received from the current subscriber
                Ok(Message::Request(payload)) => match payload.op {
                    rpc::MessageOps::Ping => {
                        subscriber.frames.send(ping_payload.clone()).await?;
                    }
                    rpc::MessageOps::Exit => {
                        info!("Shutting down server because Exit payload received");
                        self.shutdown().await;
                        return Ok(true);
                    }
                    rpc::MessageOps::Option => {
                        filter = payload.ctx;
                        subscriber
                            .frames
                            .send(rpc::Payload {
                                op: rpc::MessageOps::Debug,
                                ctx: 0,
                                data: format!("Packet filters set: {filter:#010b}").into_bytes(),
                            })
                            .await?;
                        info!(
                            "Filter set for subscriber {}: {filter:#010b}",
                            subscriber.id
                        );
                    }
                    _ => {
                        Self::handle_payload_from_subscriber(
                            payload,
                            &mut subscriber,
                            &payload_handler,
                        )
                        .await?;
                    }
                },

                // A message was received from the broadcast.
                Ok(Message::Data(payload)) => {
                    if allow_broadcast(payload.op, payload.ctx, filter) {
                        subscriber.frames.send(payload).await?;
                    }
                }
                Err(e) => {
                    error!(
                        "An error occured while processing messages for subscriber {}; error = {:?}",
                        subscriber.id, e
                    );
                }
            }
        }

        Ok(false)
    }

    /// Handle an individual subscriber
    async fn handle_subscriber<F>(
        &self,
        stream: impl AsyncRead + AsyncWrite + std::marker::Unpin,
        payload_handler: F,
    ) -> Result<()>
    where
        F: Fn(rpc::Payload) -> Result<()>,
    {
        let codec = rpc::PayloadCodec::new();
        let frames = Framed::new(stream, codec);

        let (id, rx) = self.state.lock().await.new_subscriber();
        let hello_string = self.state.lock().await.server_hello_string();

        let mut subscriber = Subscriber { id, frames, rx };

        subscriber
            .frames
            .send(
                rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx: 9000,
                    data: hello_string.into_bytes(),
                }
                .into(),
            )
            .await?;

        info!("New subscriber connected: {}", subscriber.id);

        match self
            .subscriber_msg_loop(&mut subscriber, payload_handler)
            .await
        {
            Ok(server_exit) => {
                if server_exit {
                    return Ok(());
                }
            }
            Err(e) => error!(
                "Disconecting subscriber {} because of error: {}",
                subscriber.id, e
            ),
        }

        // If this section is reached it means that the subscriber was
        // disconnected one way or another.
        {
            info!("Subscriber disconnected: {}", subscriber.id);
            let mut state = self.state.lock().await;
            state.subscribers.remove(&subscriber.id);
            // Exit once all subscribers are disconnected
            if state.subscribers.len() == 0 {
                info!("Shutting down server because last subscriber disconnected");
                self.shutdown().await;
            }
        }

        Ok(())
    }

    pub async fn run<F>(&self, pipe_name: String, payload_handler: F) -> Result<()>
    where
        F: Fn(rpc::Payload) -> Result<(), Error> + Sync + Send + Clone + 'static,
    {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx
            .set(shutdown_tx)
            .map_err(|_| format_err!("cannot run server more than once"))?;

        let (trigger, tripwire) = Tripwire::new();

        let endpoint = Endpoint::new(pipe_name);

        let incoming = endpoint.incoming()?.take_until(tripwire);

        futures::pin_mut!(incoming);

        tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
            info!("Shutdown signal received");
            trigger.cancel();
        });

        let mut subscriber_set = JoinSet::new();

        // Wait on subscribers and create a new loop task for each new
        // connection
        while let Some(result) = incoming.next().await {
            match result {
                Ok(stream) => {
                    let handler = payload_handler.clone();
                    let self_clone = self.clone();
                    subscriber_set.spawn(async move {
                        if let Err(e) = self_clone.handle_subscriber(stream, handler).await {
                            error!("Error occurred when processing stream = {:?}", e);
                        }
                    });
                }
                Err(e) => error!("Unable to connect to subscriber: {}", e),
            }
        }
        info!("Shutting down subscriber handlers");
        subscriber_set.shutdown().await;

        info!("Server shut down!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;
    use ntest::timeout;
    use rand::Rng;
    use tokio::{select, task::JoinHandle};

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
            (BroadcastFilter::AllowOther, rpc::MessageOps::RecvOther, 0),
            (BroadcastFilter::AllowOther, rpc::MessageOps::SendOther, 0),
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
        let server = Server::new();

        let fmt_msg = |a, b, c| {
            format!(
                "SERVER HELLO. HOOK STATUS: RECV {}. SEND {}. SEND_LOBBY {}.",
                a, b, c
            )
        };
        let combinations = vec![
            (false, false, false, fmt_msg("OFF", "OFF", "OFF")),
            (false, false, true, fmt_msg("OFF", "OFF", "ON")),
            (false, true, false, fmt_msg("OFF", "ON", "OFF")),
            (false, true, true, fmt_msg("OFF", "ON", "ON")),
            (true, false, false, fmt_msg("ON", "OFF", "OFF")),
            (true, false, true, fmt_msg("ON", "OFF", "ON")),
            (true, true, false, fmt_msg("ON", "ON", "OFF")),
            (true, true, true, fmt_msg("ON", "ON", "ON")),
        ];

        for (r, s, sl, expected_hello) in combinations {
            server.set_hook_status(r, s, sl).await;

            assert_eq!(
                server.state.lock().await.server_hello_string(),
                expected_hello.to_string()
            );
        }
    }

    /// Creates and runs a server. Returns the server, the pipe name,
    /// and the JoinHandle of the server.run() task.
    async fn run_server() -> (Server, String, JoinHandle<()>) {
        let server = Server::new();

        let test_id: u16 = rand::thread_rng().gen();
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", test_id);

        let server_clone = server.clone();
        let pipe_name_clone = pipe_name.clone();
        let server_handle = tokio::spawn(async move {
            server_clone
                .run(pipe_name_clone, move |_: rpc::Payload| Ok(()))
                .await
                .expect("Server should not fail to run");
        });
        // Give the server some time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        (server, pipe_name, server_handle)
    }

    async fn handle_server_hello<T>(frames: &mut Framed<T, rpc::PayloadCodec>)
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
    {
        // Handle the SERVER_HELLO message
        let message = frames.next().await.unwrap();
        if let Ok(payload) = message {
            assert_eq!(payload.ctx, 9000);
        } else {
            panic!("Did not properly receive Server Hello");
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_combined_broadcast_filters() {
        let (server, pipe_name, server_handle) = run_server().await;

        let test_handle = tokio::spawn(async move {
            let subscriber = Endpoint::connect(&pipe_name)
                .await
                .expect("Failed to connect subscriber to server");

            let codec = rpc::PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);

            handle_server_hello(&mut frames).await;

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

            let message = frames.next().await.unwrap();
            if let Ok(payload) = message {
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
                server
                    .broadcast(rpc::Payload {
                        op,
                        ctx,
                        data: Vec::new(),
                    })
                    .await;

                select! {
                    data = frames.next() => {
                        assert_eq!(should_be_allowed, true, "packet should be filtered: {:?}", data);
                    }
                    _ = tokio::time::sleep(tokio::time::Duration::from_millis(100)) => {
                        assert_eq!(should_be_allowed, false, "packet should not be filtered: {:?}: {}", op, ctx)
                    }
                }
            }
        });

        test_handle.await.expect("Test failed with assertion");
        server_handle.abort();
        let _ = server_handle.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_server_shutdown() {
        let (_, pipe_name, server_handle) = run_server().await;

        let subscriber = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect subscriber to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

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
        let _ = server_handle.await;
    }

    /// The server is expected to shut down when the last subscriber
    /// disconnects. The last subscriber must hold the connection long enough to
    /// get the SERVER_HELLO for this to be the case.
    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_subscriber_disconnect() {
        let (_, pipe_name, server_handle) = run_server().await;

        let subscriber = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect subscriber to server");
        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

        let subscriber_handle =
            tokio::spawn(async move { while let Some(_) = frames.next().await {} });

        // Disconnect the subscriber forcefully
        subscriber_handle.abort();
        let _ = subscriber_handle.await;

        let _ = server_handle.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_second_subscriber_disconnect() {
        let (server, pipe_name, server_handle) = run_server().await;

        let num_received = Arc::new(AtomicU32::new(0));

        let num_received_clone = num_received.clone();
        let pipe_name_clone = pipe_name.clone();

        let subscriber = Endpoint::connect(&pipe_name_clone)
            .await
            .expect("Failed to connect subscriber to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

        let subscriber_handle = tokio::spawn(async move {
            // Test that every packet was received in order
            while let Some(result) = frames.next().await {
                let payload = result.unwrap();
                let num_received_val = num_received_clone.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    payload.ctx, num_received_val,
                    "Received data from pipe does not match expected index!"
                );
            }
        });

        // Create and quickly drop the second subscriber
        let pipe_name_clone = pipe_name.clone();
        let second_subscriber = tokio::spawn(async move {
            let subscriber = Endpoint::connect(&pipe_name_clone)
                .await
                .expect("Failed to connect subscriber to server");

            let codec = rpc::PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);
            while let Some(_) = frames.next().await {}
        });
        second_subscriber.abort();

        // Send two packets
        for i in 0..2 {
            let mut dummy_data = Vec::from([0u8; 5000]);
            rand::thread_rng().fill(&mut dummy_data[..]);

            server
                .broadcast(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx: i,
                    data: dummy_data,
                })
                .await;
        }

        // Give some time for the subscriber to process the messages
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        subscriber_handle.abort();
        if let Err(e) = subscriber_handle.await {
            if !e.is_cancelled() {
                panic!("Test failed with assertion: {}", e);
            }
        }

        let num_received_val = num_received.load(Ordering::SeqCst);
        assert_eq!(
            num_received_val, 2,
            "two packets should be received by the subscriber"
        );

        server_handle.abort();
        let _ = server_handle.await;
    }

    /// A test to ensure the named pipe can handle a lot of data sent through
    /// the pipe before the subscriber can process it.
    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn named_pipe_load_test() {
        let (server, pipe_name, server_handle) = run_server().await;

        let test_handle = tokio::spawn(async move {
            let subscriber = Endpoint::connect(&pipe_name)
                .await
                .expect("Failed to connect subscriber to server");

            let codec = rpc::PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);

            handle_server_hello(&mut frames).await;

            // Synchronously send many packets before the subscriber can process them
            const NUM_PACKETS: u32 = 10000;
            for i in 0..NUM_PACKETS {
                let mut dummy_data = Vec::from([0u8; 5000]);
                rand::thread_rng().fill(&mut dummy_data[..]);

                server
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
                if let Ok(payload) = result {
                    assert_eq!(
                        payload.ctx, num_received,
                        "Received data from pipe does not match expected index!"
                    );
                    num_received += 1;
                    if num_received >= NUM_PACKETS {
                        return;
                    }
                }
            }
        });

        test_handle.await.expect("Test failed with assertion");

        server_handle.abort();
        let _ = server_handle.await;
    }

    /// A test to ensure the server remains stable even when creating and
    /// dropping many subscriber connections
    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn early_disconnection_stress_test() {
        let (server, pipe_name, server_handle) = run_server().await;

        // Create and quickly drop these connections
        for _ in 0..100 {
            let pipe_name_clone = pipe_name.clone();
            let sub_handle = tokio::spawn(async move {
                // If the subscriber couldn't connect it's okay
                if let Ok(subscriber) = Endpoint::connect(&pipe_name_clone).await {
                    let codec = rpc::PayloadCodec::new();
                    let mut frames = Framed::new(subscriber, codec);
                    while let Some(_) = frames.next().await {}
                }
            });
            sub_handle.abort();
        }

        let subscriber = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect subscriber to server");

        let codec = rpc::PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

        let num_received = Arc::new(AtomicU32::new(0));
        let num_received_clone = num_received.clone();
        let subscriber_handle = tokio::spawn(async move {
            // Test that every packet was received in order
            while let Some(result) = frames.next().await {
                let payload = result.unwrap();
                let num_received_val = num_received_clone.fetch_add(1, Ordering::SeqCst);
                assert_eq!(
                    payload.ctx, num_received_val,
                    "Received data from pipe does not match expected index!"
                );
            }
        });

        // Send two packets
        for i in 0..2 {
            server
                .broadcast(rpc::Payload {
                    op: rpc::MessageOps::Debug,
                    ctx: i,
                    data: Vec::new(),
                })
                .await;
        }

        // Give some time for the subscriber to process the messages
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        subscriber_handle.abort();
        if let Err(e) = subscriber_handle.await {
            if !e.is_cancelled() {
                panic!("Test failed with assertion: {}", e);
            }
        }

        let num_received_val = num_received.load(Ordering::SeqCst);
        assert_eq!(
            num_received_val, 2,
            "two packets should be received by the subscriber"
        );

        server_handle.abort();
        let _ = server_handle.await;
    }
}
