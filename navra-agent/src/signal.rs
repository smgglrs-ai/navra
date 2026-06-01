//! Cooperative signal delivery for running agents.
//!
//! Signals are delivered between iterations of the tool-use loop,
//! not preemptively. The agent checks for pending signals at the
//! top of each loop iteration and acts accordingly.

use tokio::sync::watch;

/// Signals that can be delivered to a running agent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgentSignal {
    /// No signal pending (default state).
    None,
    /// Cancel current work, return partial result.
    Interrupt,
    /// Graceful shutdown after current iteration.
    Terminate,
    /// Stop iterating until Resume is received.
    Pause,
    /// Continue after Pause (resets to None).
    Resume,
}

/// Send-side handle for delivering signals to an agent.
///
/// Retained by the caller (e.g. team registry, flow executor)
/// to control the agent externally.
#[derive(Clone)]
pub struct SignalHandle {
    tx: watch::Sender<AgentSignal>,
}

impl std::fmt::Debug for SignalHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignalHandle")
            .field("current", &*self.tx.borrow())
            .finish()
    }
}

/// Receive-side handle checked by the tool loop.
pub struct SignalReceiver {
    rx: watch::Receiver<AgentSignal>,
}

impl SignalHandle {
    /// Create a paired (handle, receiver).
    pub fn new() -> (Self, SignalReceiver) {
        let (tx, rx) = watch::channel(AgentSignal::None);
        (Self { tx }, SignalReceiver { rx })
    }

    /// Deliver a signal to the agent.
    pub fn send(&self, signal: AgentSignal) {
        let _ = self.tx.send(signal);
    }
}

impl SignalReceiver {
    /// Non-blocking check of the current signal.
    pub fn check(&self) -> AgentSignal {
        self.rx.borrow().clone()
    }

    /// Block until the signal is no longer Pause.
    pub async fn wait_for_resume(&mut self) {
        while *self.rx.borrow() == AgentSignal::Pause {
            if self.rx.changed().await.is_err() {
                // Sender dropped — treat as terminate
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_signal_is_none() {
        let (_, rx) = SignalHandle::new();
        assert_eq!(rx.check(), AgentSignal::None);
    }

    #[test]
    fn send_and_check() {
        let (tx, rx) = SignalHandle::new();
        tx.send(AgentSignal::Interrupt);
        assert_eq!(rx.check(), AgentSignal::Interrupt);
    }

    #[test]
    fn signal_handle_is_clone() {
        let (tx, rx) = SignalHandle::new();
        let tx2 = tx.clone();
        tx2.send(AgentSignal::Terminate);
        assert_eq!(rx.check(), AgentSignal::Terminate);
    }

    #[tokio::test]
    async fn pause_resume_cycle() {
        let (tx, mut rx) = SignalHandle::new();
        tx.send(AgentSignal::Pause);
        assert_eq!(rx.check(), AgentSignal::Pause);

        // Spawn a task that resumes after a short delay
        let tx2 = tx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            tx2.send(AgentSignal::Resume);
        });

        // This should block until Resume is sent
        rx.wait_for_resume().await;
        assert_eq!(rx.check(), AgentSignal::Resume);
    }

    #[tokio::test]
    async fn sender_drop_unblocks_wait() {
        let (tx, mut rx) = SignalHandle::new();
        tx.send(AgentSignal::Pause);

        // Spawn a task that drops the sender
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            drop(tx);
        });

        // wait_for_resume should return when sender is dropped
        tokio::time::timeout(std::time::Duration::from_secs(2), rx.wait_for_resume())
            .await
            .expect("wait_for_resume should return when sender is dropped");
    }
}
