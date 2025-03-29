use std::{
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use anyhow::{Result, format_err};
use deucalion::{
    namedpipe::Endpoint,
    rpc::{MessageOps, Payload, PayloadCodec},
};
use futures::{SinkExt, Stream, StreamExt};
use log::{error, info};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{OnceCell, mpsc},
};
use tokio_retry::{Retry, strategy::ExponentialBackoff};
use tokio_util::codec::Framed;

/// Shorthand for the receive half of the message channel.
type Rx = mpsc::UnboundedReceiver<Payload>;

#[derive(Debug)]
enum Message {
    /// A message requested to be sent to the connection.
    Request(Payload),

    /// A message received from the connection.
    Data(Payload),
}

/// The connection state for the subscriber.
struct Connection<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    /// The connection wrapped with the `PayloadCodec`.
    ///
    /// This handles sending and receiving data on the socket. With this codec,
    /// we can work at the Payload level instead of having to manage the
    /// raw byte operations.
    frames: Framed<T, PayloadCodec>,

    /// Receive half of the message channel.
    ///
    /// This is used to receive requests to send messages through the connection.
    rx: Rx,
}

/// Connection implements `Stream` in a way that polls both the broadcast `Rx`
/// channel and the `Framed` channel for messages sent to the named pipe by
/// a subscriber.
/// A message is produced whenever an event is ready and yields `None` when
/// the subscriber connection is closed.
impl<T> Stream for Connection<T>
where
    T: AsyncRead + AsyncWrite + std::marker::Unpin,
{
    type Item = Result<Message>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // First poll the `UnboundedReceiver`.
        if let Poll::Ready(Some(v)) = Pin::new(&mut self.rx).poll_recv(cx) {
            return Poll::Ready(Some(Ok(Message::Request(v))));
        }

        // Secondly poll the `Framed` stream.
        let result: Option<_> = futures::ready!(Pin::new(&mut self.frames).poll_next(cx));

        Poll::Ready(match result {
            // We've received some data
            Some(Ok(message)) => Some(Ok(Message::Data(message))),

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

#[repr(u32)]
pub enum BroadcastFilter {
    AllowLobbyRecv = 1,
    AllowZoneRecv = 1 << 1,
    AllowChatRecv = 1 << 2,
    AllowLobbySend = 1 << 3,
    AllowZoneSend = 1 << 4,
    AllowChatSend = 1 << 5,
    AllowOther = 1 << 6, // In case the channel is not one of [Lobby, Zone, Chat]
}

#[derive(Clone)]
pub struct Subscriber {
    shutdown_tx: Arc<OnceCell<mpsc::Sender<()>>>,
}

impl Default for Subscriber {
    fn default() -> Self {
        Self::new()
    }
}

impl Subscriber {
    pub fn new() -> Self {
        Self {
            shutdown_tx: Arc::new(OnceCell::new()),
        }
    }

    pub async fn shutdown(&self) {
        let _ = self
            .shutdown_tx
            .get()
            .expect("cannot shutdown before the subscriber is run!")
            .send(())
            .await;
    }

    /// Subscriber message loop. Returns an error if it has trouble writing
    /// to the connection.
    /// Returns true if it returned because of an Exit request. Returns false
    /// if the connection was closed naturally.
    async fn msg_loop<T, F>(
        &self,
        connection: &mut Connection<T>,
        payload_handler: F,
    ) -> Result<bool>
    where
        T: AsyncRead + AsyncWrite + std::marker::Unpin,
        F: Fn(Payload) -> Result<()>,
    {
        // Process incoming messages until our stream is exhausted by a disconnect.
        while let Some(result) = connection.next().await {
            match result {
                // A request was received from the server
                Ok(Message::Data(payload)) => match payload.op {
                    MessageOps::Debug => {
                        info!(
                            "Message from server: {}",
                            String::from_utf8_lossy(&payload.data)
                        )
                    }
                    MessageOps::Recv | MessageOps::Send => {
                        let payload_size = payload.data.len();
                        if let Err(e) = payload_handler(payload) {
                            info!("Could not process payload (size {payload_size}): {e}");
                        }
                    }
                    _ => {}
                },

                // A message was is requested to be sent to the server
                Ok(Message::Request(payload)) => {
                    connection.frames.send(payload).await?;
                }
                Err(e) => {
                    error!("An error occured while processing messages error = {e}",);
                }
            }
        }

        Ok(false)
    }

    /// Connects to the server and spawns a message handler in the background
    /// that runs until the connection is closed or the shutdown signal is
    /// invoked.
    pub async fn listen_forever<F>(
        &self,
        pipe_name: &str,
        filter: u32,
        payload_handler: F,
    ) -> Result<()>
    where
        F: Fn(Payload) -> Result<()> + Sync + Send + 'static,
    {
        let (shutdown_tx, mut shutdown_rx) = mpsc::channel(1);
        self.shutdown_tx
            .set(shutdown_tx)
            .map_err(|_| format_err!("cannot run subscriber more than once"))?;

        let subscriber = Retry::spawn(
            ExponentialBackoff::from_millis(10)
                .max_delay(Duration::from_secs(1))
                .take(8),
            || Endpoint::connect(pipe_name),
        )
        .await?;

        // Create a frame decoder that processes the subscriber stream
        let codec = PayloadCodec::new();
        let mut frames = Framed::new(subscriber, codec);

        // Handle the SERVER_HELLO message
        let hello_message = frames
            .next()
            .await
            .ok_or(format_err!("Couldn't get next frame"))??;
        if hello_message.ctx != HELLO_CHANNEL {
            return Err(format_err!("First message wasn't a server hello?"));
        }
        info!(
            "Message from server: {}",
            String::from_utf8_lossy(&hello_message.data)
        );

        let (tx, rx) = mpsc::unbounded_channel();

        let mut connection = Connection { frames, rx };

        tx.send(dbg_payload(
            HELLO_CHANNEL,
            "DEUCALION_CLIENT".as_bytes().into(),
        ))?;
        tx.send(Payload {
            op: MessageOps::Option,
            ctx: filter,
            data: Vec::new(),
        })?;

        let self_clone = self.clone();
        let msg_loop_task = tokio::spawn(async move {
            if let Err(e) = self_clone.msg_loop(&mut connection, payload_handler).await {
                error!("Error occurred during message loop: {e}");
            }
        });

        let msg_loop_abort_handle = msg_loop_task.abort_handle();

        tokio::spawn(async move {
            let _ = shutdown_rx.recv().await;
            info!("Shutdown signal received");
            msg_loop_abort_handle.abort();
        });

        msg_loop_task.await?;
        Ok(())
    }
}
