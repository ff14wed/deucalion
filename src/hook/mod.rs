use crossbeam_channel as channel;
use failure::Error;

use crate::rpc;

mod recvzonepacket;
mod waitgroup;

pub struct State {
    rzp_hook: recvzonepacket::Hook,
    wg: waitgroup::WaitGroup,
    pub broadcast_rx: channel::Receiver<rpc::Payload>,
}

impl State {
    pub fn new() -> Result<State, Error> {
        let (broadcast_tx, broadcast_rx) = channel::unbounded::<rpc::Payload>();

        let wg = waitgroup::WaitGroup::new();
        let hs = State {
            rzp_hook: recvzonepacket::Hook::new(broadcast_tx.clone(), wg.clone())?,
            wg,
            broadcast_rx,
        };
        hs.rzp_hook.setup()?;
        Ok(hs)
    }

    pub fn shutdown(&self) {
        self.rzp_hook.shutdown();
        // Wait for any hooks to finish what they're doing
        self.wg.wait();
    }
}
