/*
This implementation was adapted from
https://github.com/paritytech/parity-tokio-ipc/ under the following license:

Copyright (c) 2017 Nikolay Volf

Permission is hereby granted, free of charge, to any
person obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without
limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software
is furnished to do so, subject to the following
conditions:

The above copyright notice and this permission notice
shall be included in all copies or substantial portions
of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF
ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED
TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
*/

use winapi::shared::winerror::ERROR_PIPE_BUSY;

use futures::Stream;
use std::io;
use std::path::Path;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};

use tokio::net::windows::named_pipe;

enum NamedPipe {
    Server(named_pipe::NamedPipeServer),
    Client(named_pipe::NamedPipeClient),
}

const PIPE_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(5);

/// Endpoint implementation for windows
pub struct Endpoint {
    path: String,
    created_listener: bool,
}

impl Endpoint {
    /// Stream of incoming connections
    pub fn incoming(
        mut self,
    ) -> io::Result<impl Stream<Item = io::Result<impl AsyncRead + AsyncWrite>> + 'static> {
        let pipe = self.create_listener()?;

        let stream =
            futures::stream::try_unfold((pipe, self), |(listener, mut endpoint)| async move {
                listener.connect().await?;

                let new_listener = endpoint.create_listener()?;

                let conn = Connection::wrap(NamedPipe::Server(listener));

                Ok(Some((conn, (new_listener, endpoint))))
            });

        Ok(stream)
    }

    fn create_listener(&mut self) -> io::Result<named_pipe::NamedPipeServer> {
        let server = named_pipe::ServerOptions::new()
            .first_pipe_instance(!self.created_listener)
            .reject_remote_clients(true)
            .access_inbound(true)
            .access_outbound(true)
            .in_buffer_size(65536)
            .out_buffer_size(65536)
            .create(&self.path)?;
        self.created_listener = true;

        Ok(server)
    }

    /// Make new connection using the provided path and running event pool.
    #[allow(dead_code)]
    pub async fn connect<P: AsRef<Path>>(path: P) -> io::Result<Connection> {
        let path = path.as_ref();

        // There is not async equivalent of waiting for a named pipe in Windows,
        // so we keep trying or sleeping for a bit, until we hit a timeout
        let attempt_start = Instant::now();
        let client = loop {
            match named_pipe::ClientOptions::new()
                .read(true)
                .write(true)
                .open(path)
            {
                Ok(client) => break client,
                Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY as i32) => {
                    if attempt_start.elapsed() < PIPE_AVAILABILITY_TIMEOUT {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    } else {
                        return Err(e);
                    }
                }
                Err(e) => return Err(e),
            }
        };

        Ok(Connection::wrap(NamedPipe::Client(client)))
    }

    /// New IPC endpoint at the given path
    pub fn new(path: String) -> Self {
        Endpoint {
            path,
            created_listener: false,
        }
    }
}

/// IPC connection.
pub struct Connection {
    inner: NamedPipe,
}

impl Connection {
    /// Wraps an existing named pipe
    fn wrap(pipe: NamedPipe) -> Self {
        Self { inner: pipe }
    }
}

impl AsyncRead for Connection {
    fn poll_read(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = Pin::into_inner(self);
        match this.inner {
            NamedPipe::Client(ref mut c) => Pin::new(c).poll_read(ctx, buf),
            NamedPipe::Server(ref mut s) => Pin::new(s).poll_read(ctx, buf),
        }
    }
}

impl AsyncWrite for Connection {
    fn poll_write(
        self: Pin<&mut Self>,
        ctx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, io::Error>> {
        let this = Pin::into_inner(self);
        match this.inner {
            NamedPipe::Client(ref mut c) => Pin::new(c).poll_write(ctx, buf),
            NamedPipe::Server(ref mut s) => Pin::new(s).poll_write(ctx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = Pin::into_inner(self);
        match this.inner {
            NamedPipe::Client(ref mut c) => Pin::new(c).poll_flush(ctx),
            NamedPipe::Server(ref mut s) => Pin::new(s).poll_flush(ctx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, ctx: &mut Context<'_>) -> Poll<Result<(), io::Error>> {
        let this = Pin::into_inner(self);
        match this.inner {
            NamedPipe::Client(ref mut c) => Pin::new(c).poll_shutdown(ctx),
            NamedPipe::Server(ref mut s) => Pin::new(s).poll_shutdown(ctx),
        }
    }
}
