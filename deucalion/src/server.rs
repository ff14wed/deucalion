use std::{
    collections::HashMap,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{Error, Result, format_err};
use futures::{SinkExt, Stream, StreamExt};
use log::{error, info};
use once_cell::sync::OnceCell;
use stream_cancel::Tripwire;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex, mpsc},
    task::JoinSet,
    time::{self, Duration},
};
use tokio_util::codec::Framed;

use crate::{
    namedpipe::Endpoint,
    rpc::{MessageOps, Payload, PayloadCodec},
};

/// Shorthand for the transmit half of the message channel.
type Tx = mpsc::UnboundedSender<Payload>;
/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<Payload>;

#[derive(Debug)]
enum Message {
    /// A message that was sent from a subscriber to the server
    Request(Payload),
    /// A message that should be sent to subscribers
    Data(Payload),
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
    frames: Framed<T, PayloadCodec>,
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

const HELLO_CHANNEL: u32 = 9000;

fn dbg_payload(ctx: u32, data: Vec<u8>) -> Payload {
    let op = MessageOps::Debug;
    Payload { op, ctx, data }
}

fn ping_payload() -> Payload {
    Payload { op: MessageOps::Ping, ctx: 0, data: vec![] }
}

/// Checks to make sure that the UTF-8 string is 30 characters or less and is
/// ASCII alphanumeric with underscores allowwed
fn validate_nickname(nickname: &str) -> Result<()> {
    if nickname.len() > 30 {
        return Err(format_err!("Nickname exceeds 30 chars: {nickname:?}"));
    }
    if !nickname.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format_err!(
            "Nickname contains invalid characters: {nickname:?}"
        ));
    }
    Ok(())
}

impl<T> Subscriber<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    async fn send_dbg_payload(&mut self, ctx: u32, data: Vec<u8>) -> Result<()> {
        self.frames.send(dbg_payload(ctx, data)).await?;
        Ok(())
    }

    /// Handle the nickname sent from the subscriber and send a success/failure
    /// response back.
    async fn handle_nickname(&mut self, payload: Payload, nickname: &mut String) -> Result<()>
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
    {
        let bytes_str = format!("{:?}", payload.data);
        match String::from_utf8(payload.data) {
            Ok(nickname_str) => {
                if let Err(e) = validate_nickname(&nickname_str) {
                    self.send_dbg_payload(
                        HELLO_CHANNEL,
                        format!("INVALID NICKNAME: \"{nickname_str}\"").into(),
                    )
                    .await?;
                    return Err(e);
                }
                *nickname = format!("{nickname_str} (subscriber {})", self.id);
                self.send_dbg_payload(
                    HELLO_CHANNEL,
                    format!("CHANGED NICKNAME: {nickname}").into(),
                )
                .await?;
            }
            Err(e) => {
                self.send_dbg_payload(
                    HELLO_CHANNEL,
                    format!("INVALID NICKNAME: {bytes_str}").into(),
                )
                .await?;
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Handle the payload from subscriber and send a success/failure response back
    async fn handle_payload<F>(&mut self, payload: Payload, payload_handler: &F) -> Result<()>
    where
        F: Fn(Payload) -> Result<()>,
    {
        let ctx = payload.ctx;
        let ack_prefix = match payload.op {
            MessageOps::Recv => "RECV ",
            MessageOps::Send => "SEND ",
            _ => "",
        };
        let debug_payload = match payload_handler(payload) {
            Ok(()) => format!("{ack_prefix}OK"),
            Err(e) => format!("{ack_prefix}{e}"),
        };
        self.send_dbg_payload(ctx, debug_payload.into()).await?;
        Ok(())
    }
}

#[allow(clippy::enum_variant_names)]
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

fn allow_broadcast(op: MessageOps, channel: u32, filter: u32) -> bool {
    match op {
        MessageOps::Recv => match channel {
            0 => (filter & BroadcastFilter::AllowLobbyRecv as u32) > 0,
            1 => (filter & BroadcastFilter::AllowZoneRecv as u32) > 0,
            2 => (filter & BroadcastFilter::AllowChatRecv as u32) > 0,
            _ => (filter & BroadcastFilter::AllowOther as u32) > 0,
        },
        MessageOps::Send => match channel {
            0 => (filter & BroadcastFilter::AllowLobbySend as u32) > 0,
            1 => (filter & BroadcastFilter::AllowZoneSend as u32) > 0,
            2 => (filter & BroadcastFilter::AllowChatSend as u32) > 0,
            _ => (filter & BroadcastFilter::AllowOther as u32) > 0,
        },
        MessageOps::RecvOther => (filter & BroadcastFilter::AllowOther as u32) > 0,
        MessageOps::SendOther => (filter & BroadcastFilter::AllowOther as u32) > 0,
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
    create_target_hooked: bool,
}

impl State {
    fn claim_id(&mut self) -> usize {
        let original = self.counter;
        self.counter += 1;
        original
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
        if status { "ON" } else { "OFF" }
    }

    fn server_hello_string(&self) -> String {
        format!(
            "SERVER HELLO. VERSION: {}. HOOK STATUS: RECV {}. SEND {}. SEND_LOBBY {}. CREATE_TARGET {}.",
            crate::VERSION,
            Self::hook_status_string(self.recv_hooked),
            Self::hook_status_string(self.send_hooked),
            Self::hook_status_string(self.send_lobby_hooked),
            Self::hook_status_string(self.create_target_hooked),
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
                create_target_hooked: false,
            })),
            shutdown_tx: OnceCell::new(),
        }
    }

    /// Notifies the server of the hook status.
    pub async fn set_hook_status(&self, r: bool, s: bool, sl: bool, ct: bool) {
        let mut state = self.state.lock().await;
        state.recv_hooked = r;
        state.send_hooked = s;
        state.send_lobby_hooked = sl;
        state.create_target_hooked = ct;
    }

    pub async fn shutdown(&self) {
        let _ = self
            .shutdown_tx
            .get()
            .expect("cannot shutdown before the server is run!")
            .send(())
            .await;
    }

    pub async fn broadcast(&self, message: Payload) {
        let mut state = self.state.lock().await;
        for subscriber in state.subscribers.iter_mut() {
            let _ = subscriber.1.send(message.clone());
        }
    }

    /// Subscriber message loop. Returns an error if it has trouble writing
    /// to the connection.
    /// Returns true if it returned because of an Exit request. Returns false
    /// if the connection was closed naturally.
    async fn subscriber_msg_loop<T, F>(
        &self,
        subscriber: &mut Subscriber<T>,
        nickname: &mut String,
        payload_handler: F,
    ) -> Result<bool>
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
        F: Fn(Payload) -> Result<()>,
    {
        // Default packet filter is AllowZoneRecv only
        let mut filter: u32 = BroadcastFilter::AllowZoneRecv as u32;

        // Process incoming messages until our stream is exhausted by a disconnect.
        while let Some(result) = subscriber.next().await {
            match result {
                // A request was received from the current subscriber
                Ok(Message::Request(payload)) => match payload.op {
                    MessageOps::Ping => {
                        subscriber.frames.send(ping_payload()).await?;
                    }
                    MessageOps::Exit => {
                        info!("Shutting down server because Exit payload received");
                        self.shutdown().await;
                        return Ok(true);
                    }
                    MessageOps::Option => {
                        filter = payload.ctx;
                        subscriber
                            .send_dbg_payload(
                                0,
                                format!("Packet filters set: {filter:#010b}").into(),
                            )
                            .await?;
                        info!("Filter set for {nickname}: {filter:#010b}");
                    }
                    MessageOps::Debug if payload.ctx == HELLO_CHANNEL => {
                        if let Err(e) = subscriber.handle_nickname(payload, nickname).await {
                            error!("Error setting nickname for {nickname}: {e}")
                        } else {
                            info!(
                                "Changed nickname for subscriber {} to {nickname}",
                                subscriber.id
                            )
                        }
                    }
                    _ => {
                        info!("Received payload from {nickname}: {payload:?}");
                        subscriber.handle_payload(payload, &payload_handler).await?;
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
                        "An error occured while processing messages for {nickname}; error = {e}",
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
        F: Fn(Payload) -> Result<()>,
    {
        let codec = PayloadCodec::new();
        let frames = Framed::new(stream, codec);

        let (id, rx) = self.state.lock().await.new_subscriber();
        let hello_string = self.state.lock().await.server_hello_string();

        let mut subscriber = Subscriber { id, frames, rx };
        let mut nickname = format!("subscriber {}", subscriber.id);

        subscriber
            .send_dbg_payload(HELLO_CHANNEL, hello_string.into())
            .await
            .map_err(|e| format_err!("Could not send SERVER HELLO to {nickname}: {e}"))?;

        info!("New subscriber connected: {nickname}");

        match self.subscriber_msg_loop(&mut subscriber, &mut nickname, payload_handler).await {
            Ok(server_exit) => {
                if server_exit {
                    return Ok(());
                }
            }
            Err(e) => error!("Disconecting {nickname} because of error: {e}"),
        }

        // If this section is reached it means that the subscriber was
        // disconnected one way or another.
        {
            info!("Disconnected: {nickname}");
            let mut state = self.state.lock().await;
            state.subscribers.remove(&subscriber.id);
            // Exit once all subscribers are disconnected
            if state.subscribers.is_empty() {
                info!("Shutting down server because last subscriber disconnected");
                self.shutdown().await;
            }
        }

        Ok(())
    }

    pub async fn run<F>(
        &self,
        pipe_name: String,
        enable_ping: bool,
        payload_handler: F,
    ) -> Result<()>
    where
        F: Fn(Payload) -> Result<(), Error> + Sync + Send + Clone + 'static,
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

        let self_clone = self.clone();
        let ping_task = tokio::spawn(async move {
            if enable_ping {
                let mut interval = time::interval(Duration::from_secs(1));

                loop {
                    interval.tick().await;
                    self_clone
                        .broadcast(Payload { op: MessageOps::Ping, ctx: 0, data: vec![] })
                        .await;
                }
            }
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
                            error!("Error occurred when processing stream = {e}");
                        }
                    });
                }
                Err(e) => error!("Unable to connect to subscriber: {e}"),
            }
        }

        info!("Aborting ping task");
        ping_task.abort();
        let _ = ping_task.await;

        info!("Shutting down subscriber handlers");
        subscriber_set.shutdown().await;

        info!("Server shut down!");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use ntest::{assert_false, assert_true, timeout};
    use rand::Rng;
    use tokio::{select, task::JoinHandle};

    use super::*;

    #[test]
    fn test_individual_packet_filters() {
        let configurations = [
            (BroadcastFilter::AllowLobbyRecv, MessageOps::Recv, 0),
            (BroadcastFilter::AllowZoneRecv, MessageOps::Recv, 1),
            (BroadcastFilter::AllowChatRecv, MessageOps::Recv, 2),
            (BroadcastFilter::AllowLobbySend, MessageOps::Send, 0),
            (BroadcastFilter::AllowZoneSend, MessageOps::Send, 1),
            (BroadcastFilter::AllowChatSend, MessageOps::Send, 2),
            (BroadcastFilter::AllowOther, MessageOps::Recv, 100),
            (BroadcastFilter::AllowOther, MessageOps::RecvOther, 0),
            (BroadcastFilter::AllowOther, MessageOps::SendOther, 0),
        ];
        const ALLOW_EVERYTHING: u32 = 0xFF;
        for (filter, op, ctx) in configurations {
            let filter = filter as u32;
            assert_true!(allow_broadcast(op, ctx, ALLOW_EVERYTHING));
            assert_true!(allow_broadcast(op, ctx, filter));
            assert_false!(allow_broadcast(op, ctx, ALLOW_EVERYTHING & !filter));
        }
    }

    #[test]
    fn test_nickname_validation() {
        let nickname_tests = [
            ("Inquisitor1234", None),
            ("Names_with_underscores", None),
            (
                "Names with spaces",
                Some("Nickname contains invalid characters: \"Names with spaces\""),
            ),
            (
                "Names.with.punctuation.marks",
                Some("Nickname contains invalid characters: \"Names.with.punctuation.marks\""),
            ),
            (
                "ASCIIではありません",
                Some("Nickname contains invalid characters: \"ASCIIではありません\""),
            ),
            (
                "This_name_is_over_30_chars_long",
                Some("Nickname exceeds 30 chars: \"This_name_is_over_30_chars_long\""),
            ),
        ];
        for (nickname, expected_err) in nickname_tests {
            match validate_nickname(nickname) {
                Ok(()) => {
                    if let Some(err_msg) = expected_err {
                        panic!("Expected validation for {nickname} to error with {err_msg}");
                    }
                }
                Err(e) => match expected_err {
                    Some(msg) => assert_eq!(e.to_string(), msg),
                    None => panic!("Expected validation for {nickname} to succeed but got err {e}"),
                },
            }
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_server_hello_message() {
        let server = Server::new();

        let fmt_msg = |a, b, c, d| {
            format!(
                "SERVER HELLO. VERSION: {}. HOOK STATUS: RECV {a}. SEND {b}. SEND_LOBBY {c}. CREATE_TARGET {d}.",
                crate::VERSION,
            )
        };
        let combinations = vec![
            (false, false, true, true, fmt_msg("OFF", "OFF", "ON", "ON")),
            (false, true, false, true, fmt_msg("OFF", "ON", "OFF", "ON")),
            (false, true, true, true, fmt_msg("OFF", "ON", "ON", "ON")),
            (true, false, false, true, fmt_msg("ON", "OFF", "OFF", "ON")),
            (true, false, true, true, fmt_msg("ON", "OFF", "ON", "ON")),
            (true, true, false, true, fmt_msg("ON", "ON", "OFF", "ON")),
            (true, true, true, true, fmt_msg("ON", "ON", "ON", "ON")),
            (true, true, true, false, fmt_msg("ON", "ON", "ON", "OFF")),
        ];

        for (r, s, sl, ct, expected_hello) in combinations {
            server.set_hook_status(r, s, sl, ct).await;

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

        let test_id: u16 = rand::rng().random();
        let pipe_name = format!(r"\\.\pipe\deucalion-test-{}", test_id);

        let server_clone = server.clone();
        let pipe_name_clone = pipe_name.clone();
        let server_handle = tokio::spawn(async move {
            server_clone
                .run(pipe_name_clone, false, move |_: Payload| Ok(()))
                .await
                .expect("Server should not fail to run");
        });
        // Give the server some time to start
        time::sleep(Duration::from_millis(100)).await;

        (server, pipe_name, server_handle)
    }

    async fn handle_server_hello<T>(frames: &mut Framed<T, PayloadCodec>)
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
    {
        // Handle the SERVER_HELLO message
        let message = frames.next().await.unwrap();
        let payload = message.expect("Server Hello should be properly received");
        assert_eq!(payload.ctx, HELLO_CHANNEL);
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_combined_broadcast_filters() {
        let (server, pipe_name, server_handle) = run_server().await;

        let test_handle = tokio::spawn(async move {
            let subscriber = Endpoint::connect(&pipe_name)
                .await
                .expect("Failed to connect subscriber to server");

            let codec = PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);

            handle_server_hello(&mut frames).await;

            let filter = BroadcastFilter::AllowChatRecv as u32
                | BroadcastFilter::AllowChatSend as u32
                | BroadcastFilter::AllowZoneRecv as u32;

            // Send option
            frames
                .send(Payload { op: MessageOps::Option, ctx: filter, data: vec![] })
                .await
                .unwrap();

            let message = frames.next().await.unwrap();
            if let Ok(payload) = message {
                assert_eq!(payload.op, MessageOps::Debug);
                assert_eq!(
                    String::from_utf8(payload.data).unwrap(),
                    "Packet filters set: 0b00100110",
                );
            } else {
                panic!("Did not properly receive packet filter confirmation");
            }

            let configurations = vec![
                (MessageOps::Recv, 0, false),
                (MessageOps::Recv, 1, true),
                (MessageOps::Recv, 2, true),
                (MessageOps::Send, 0, false),
                (MessageOps::Send, 1, false),
                (MessageOps::Send, 2, true),
                (MessageOps::Recv, 100, false),
            ];

            for (op, ctx, should_be_allowed) in configurations {
                server.broadcast(Payload { op, ctx, data: vec![] }).await;

                select! {
                    data = frames.next() => {
                        assert!(should_be_allowed, "packet should be filtered: {:?}", data);
                    }
                    _ = time::sleep(Duration::from_millis(100)) => {
                        assert!(!should_be_allowed, "packet should not be filtered: {:?}: {}", op, ctx)
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
    async fn test_subscriber_nickname() {
        let (_, pipe_name, server_handle) = run_server().await;

        // (nickname, expected message)
        let testcases: Vec<(Vec<u8>, &str)> = vec![
            (
                "Inquisitor1234".into(),
                "CHANGED NICKNAME: Inquisitor1234 (subscriber 0)",
            ),
            (
                "Names_with_underscores".into(),
                "CHANGED NICKNAME: Names_with_underscores (subscriber 0)",
            ),
            (
                // Invalid UTF-8 string not allowed
                vec![0, 150, 200, 250],
                "INVALID NICKNAME: [0, 150, 200, 250]",
            ),
            (
                // Names with spaces not allowed
                "Names with spaces".into(),
                "INVALID NICKNAME: \"Names with spaces\"",
            ),
            (
                // Names with other symbols not allowed
                "Names.with.punctuation.marks".into(),
                "INVALID NICKNAME: \"Names.with.punctuation.marks\"",
            ),
            (
                // Names over 30 characters not allowed
                "This_name_is_over_30_chars_long".into(),
                "INVALID NICKNAME: \"This_name_is_over_30_chars_long\"",
            ),
        ];
        let test_handle = tokio::spawn(async move {
            let subscriber = Endpoint::connect(&pipe_name)
                .await
                .expect("Failed to connect subscriber to server");

            let codec = PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);

            handle_server_hello(&mut frames).await;

            for (nickname, expected_resp) in testcases {
                frames.send(dbg_payload(HELLO_CHANNEL, nickname)).await.unwrap();

                let message = frames.next().await.unwrap();
                if let Ok(payload) = message {
                    assert_eq!(payload.op, MessageOps::Debug);
                    assert_eq!(
                        String::from_utf8(payload.data).unwrap(),
                        expected_resp,
                        "Expected response did not match"
                    );
                } else {
                    panic!("Did not receive subscriber nickname confirmation");
                }
            }
        });

        test_handle.await.expect("Test failed with assertion");
        server_handle.abort();

        // Wait on the server to shut down
        let _ = server_handle.await;
    }

    #[tokio::test(flavor = "multi_thread")]
    #[timeout(10_000)]
    async fn test_server_shutdown() {
        let (_, pipe_name, server_handle) = run_server().await;

        let subscriber = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect subscriber to server");

        let codec = PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

        // Send exit
        frames
            .send(Payload { op: MessageOps::Exit, ctx: 0, data: vec![] })
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
        let codec = PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        handle_server_hello(&mut frames).await;

        let subscriber_handle = tokio::spawn(async move { while frames.next().await.is_some() {} });

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

        let codec = PayloadCodec::new();
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

            let codec = PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);
            while frames.next().await.is_some() {}
        });
        second_subscriber.abort();

        // Send two packets
        for i in 0..2 {
            let mut dummy_data = Vec::from([0u8; 5000]);
            rand::rng().fill(&mut dummy_data[..]);
            server.broadcast(dbg_payload(i, dummy_data)).await;
        }

        // Give some time for the subscriber to process the messages
        time::sleep(Duration::from_millis(100)).await;

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

            let codec = PayloadCodec::new();
            let mut frames = Framed::new(subscriber, codec);

            handle_server_hello(&mut frames).await;

            // Synchronously send many packets before the subscriber can process them
            const NUM_PACKETS: u32 = 10000;
            for i in 0..NUM_PACKETS {
                let mut dummy_data = Vec::from([0u8; 5000]);
                rand::rng().fill(&mut dummy_data[..]);
                server.broadcast(dbg_payload(i, dummy_data)).await;
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
                    let codec = PayloadCodec::new();
                    let mut frames = Framed::new(subscriber, codec);
                    while frames.next().await.is_some() {}
                }
            });
            sub_handle.abort();
        }

        let subscriber = Endpoint::connect(&pipe_name)
            .await
            .expect("Failed to connect subscriber to server");

        let codec = PayloadCodec::new();
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
            server.broadcast(dbg_payload(i, vec![])).await;
        }

        // Give some time for the subscriber to process the messages
        time::sleep(Duration::from_millis(100)).await;

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
