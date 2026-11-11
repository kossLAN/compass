use std::sync::Arc;

use tokio::sync::watch;

#[derive(Debug, Clone, Copy, Default)]
struct State {
    suspended: bool,
    generation: u64,
}

#[derive(Debug, Clone, Default)]
pub struct Readiness(Arc<watch::Sender<State>>);

impl Readiness {
    pub fn suspend(&self) -> Suspended {
        self.0.send_modify(|state| {
            state.suspended = true;
            state.generation += 1;
        });
        Suspended(self.clone())
    }

    pub async fn ready(&self) -> u64 {
        self.0
            .subscribe()
            .wait_for(|state| !state.suspended)
            .await
            .map_or_else(|_| self.generation(), |state| state.generation)
    }

    pub fn generation(&self) -> u64 {
        self.0.borrow().generation
    }
}

pub struct Suspended(Readiness);

impl Drop for Suspended {
    fn drop(&mut self) {
        self.0.0.send_modify(|state| state.suspended = false);
    }
}
