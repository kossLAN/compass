use std::collections::{HashMap, VecDeque};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use bunnyhop_proto::{NodeId, SignalDelivery, SignalMessage};
use tokio::sync::watch;

const CAPACITY: usize = 256;
const MAX_AGE: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct Mailboxes {
    inner: Mutex<HashMap<NodeId, Mailbox>>,
}

struct Mailbox {
    queue: VecDeque<(Instant, SignalDelivery)>,
    pushed: watch::Sender<()>,
}

impl Default for Mailbox {
    fn default() -> Self {
        Self {
            queue: VecDeque::new(),
            pushed: watch::Sender::new(()),
        }
    }
}

impl Mailbox {
    fn is_idle(&self) -> bool {
        self.queue.is_empty() && self.pushed.receiver_count() == 0
    }
}

impl Mailboxes {
    pub fn push(&self, to: NodeId, from: NodeId, message: SignalMessage) {
        let mut mailboxes = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        let mailbox = mailboxes.entry(to).or_default();

        if mailbox.queue.len() == CAPACITY {
            mailbox.queue.pop_front();
        }

        mailbox
            .queue
            .push_back((Instant::now(), SignalDelivery { from, message }));
        mailbox.pushed.send_replace(());
    }

    pub fn subscribe(&self, id: NodeId) -> watch::Receiver<()> {
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .entry(id)
            .or_default()
            .pushed
            .subscribe()
    }

    pub fn take(&self, id: NodeId) -> Vec<SignalDelivery> {
        let now = Instant::now();
        let mut mailboxes = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        mailboxes
            .get_mut(&id)
            .map(|mailbox| {
                mailbox
                    .queue
                    .drain(..)
                    .filter(|(at, _)| is_fresh(now, *at))
                    .map(|(_, delivery)| delivery)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn sweep(&self) {
        let now = Instant::now();
        self.inner
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .retain(|_, mailbox| {
                mailbox.queue.retain(|(at, _)| is_fresh(now, *at));
                !mailbox.is_idle()
            });
    }
}

fn is_fresh(now: Instant, at: Instant) -> bool {
    now.duration_since(at) < MAX_AGE
}
