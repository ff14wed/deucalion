use std::env;

use deucalion::{namedpipe::Endpoint, rpc};
use futures::{SinkExt, StreamExt};
use tokio_util::codec::Framed;

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        panic!("1 positional arg is required. See usage in the README.")
    }
    let process_id = &args[1].parse::<u32>().unwrap();

    let pipe_name = format!(r"\\.\pipe\deucalion-{process_id}");
    signal_pipe(&pipe_name).await;
}

async fn signal_pipe(pipe_name: &str) {
    let subscriber = Endpoint::connect(pipe_name)
        .await
        .expect("Failed to connect subscriber to server");

    // Create a frame decoder that processes the subscriber stream
    let codec = rpc::PayloadCodec::new();
    let mut frames = Framed::new(subscriber, codec);

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
}
