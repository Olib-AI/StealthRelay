//! Hands each connection's frames to the handler in the order they arrived.
//!
//! A client sends its frames in an order that means something: a host says yes to a join and then
//! ends the link it used. Handling each frame in its own task lets the second overtake the first,
//! and the person the host just let in is told their link is no longer valid. So one connection's
//! frames run one at a time, while different connections still run side by side.
//!
//! Tunnel control frames stay concurrent: opening a stream can wait on a remote host for many
//! seconds, and a pool's messages must not wait behind that.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use stealthos_core::types::ConnectionId;
use tokio::sync::mpsc;

/// One frame from one connection.
pub struct Frame {
    pub connection_id: ConnectionId,
    pub remote_addr: SocketAddr,
    pub message: String,
}

/// Runs `handle` for each frame, in arrival order per connection.
pub struct ConnectionDispatcher<H> {
    handle: Arc<H>,
    queues: HashMap<ConnectionId, mpsc::UnboundedSender<Frame>>,
}

impl<H, Fut> ConnectionDispatcher<H>
where
    H: Fn(Frame) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    pub fn new(handle: H) -> Self {
        Self {
            handle: Arc::new(handle),
            queues: HashMap::new(),
        }
    }

    /// Queues a frame behind the ones its connection already sent.
    pub fn dispatch(&mut self, frame: Frame) {
        if frame.message.contains("tunnel_") {
            let handle = Arc::clone(&self.handle);
            tokio::spawn(async move { handle(frame).await });
            return;
        }
        let connection_id = frame.connection_id;
        let queue = self.queues.entry(connection_id).or_insert_with(|| {
            let (sender, mut receiver) = mpsc::unbounded_channel::<Frame>();
            let handle = Arc::clone(&self.handle);
            tokio::spawn(async move {
                while let Some(frame) = receiver.recv().await {
                    handle(frame).await;
                }
            });
            sender
        });
        // The worker lives as long as its sender, so this can't fail while the entry exists.
        let _ = queue.send(frame);
    }

    /// The connection is gone. What it already sent still runs, then its worker ends.
    pub fn forget(&mut self, connection_id: ConnectionId) {
        self.queues.remove(&connection_id);
    }

    #[cfg(test)]
    fn queue_count(&self) -> usize {
        self.queues.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use std::time::Duration;

    fn frame(connection: u64, message: &str) -> Frame {
        Frame {
            connection_id: ConnectionId(connection),
            remote_addr: "127.0.0.1:1".parse().unwrap(),
            message: message.to_owned(),
        }
    }

    /// A frame called "slow" takes a while. Records when each finishes.
    fn recording_dispatcher(
        log: &Arc<Mutex<Vec<String>>>,
    ) -> ConnectionDispatcher<
        impl Fn(Frame) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync + 'static,
    > {
        let log = Arc::clone(log);
        ConnectionDispatcher::new(move |frame: Frame| {
            let log = Arc::clone(&log);
            Box::pin(async move {
                if frame.message.contains("slow") {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                log.lock().unwrap().push(frame.message);
            }) as std::pin::Pin<Box<dyn Future<Output = ()> + Send>>
        })
    }

    #[tokio::test]
    async fn a_connections_frames_run_in_the_order_they_came() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = recording_dispatcher(&log);
        dispatcher.dispatch(frame(1, "slow join_approval"));
        dispatcher.dispatch(frame(1, "revoke_invitation"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            *log.lock().unwrap(),
            vec!["slow join_approval", "revoke_invitation"]
        );
    }

    #[tokio::test]
    async fn one_connection_does_not_wait_for_another() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = recording_dispatcher(&log);
        dispatcher.dispatch(frame(1, "slow first"));
        dispatcher.dispatch(frame(2, "second"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*log.lock().unwrap(), vec!["second", "slow first"]);
    }

    #[tokio::test]
    async fn tunnel_frames_do_not_hold_up_a_pools_messages() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = recording_dispatcher(&log);
        dispatcher.dispatch(frame(1, "slow tunnel_open"));
        dispatcher.dispatch(frame(1, "forward"));
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*log.lock().unwrap(), vec!["forward", "slow tunnel_open"]);
    }

    #[tokio::test]
    async fn what_a_gone_connection_sent_still_runs_and_its_queue_goes() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let mut dispatcher = recording_dispatcher(&log);
        dispatcher.dispatch(frame(1, "slow last words"));
        assert_eq!(dispatcher.queue_count(), 1);
        dispatcher.forget(ConnectionId(1));
        assert_eq!(dispatcher.queue_count(), 0);
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(*log.lock().unwrap(), vec!["slow last words"]);
    }
}
