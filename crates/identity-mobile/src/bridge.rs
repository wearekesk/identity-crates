//! Driving a blocking read from a host whose NFC is asynchronous.
//!
//! `flutter_nfc_kit`, `CoreNFC` and Android's `IsoDep` wrapped in Kotlin coroutines all
//! hand back a future. The passport protocol, by contrast, is a conversation: read a
//! file, derive a key, read the next. `dmrtd` models that as blocking calls, which is
//! the right shape for a protocol and the wrong shape for a Dart `Future`.
//!
//! The bridge closes the gap without either side pretending to be the other:
//!
//! 1. The host calls [`crate::ffi::identity_mobile_read_passport_async`] **on a worker
//!    thread** — `Isolate.run` in Dart. Blocking there is free.
//! 2. Each APDU is posted to the host with an exchange id, and the calling thread
//!    parks.
//! 3. The host's main isolate does its `await`, then calls
//!    [`crate::ffi::identity_mobile_supply_apdu`] with the answer, which wakes the
//!    worker.
//!
//! The alternative — insisting on a synchronous transceive — rules out every Flutter
//! NFC package there is.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

/// How long a single APDU may take before the read is abandoned.
///
/// Generous, because a DG2 read over NFC is genuinely slow and a holder repositioning
/// the phone is normal. Not unbounded, because a host that drops an exchange would
/// otherwise park a thread forever.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// What the host sends back for one exchange.
type Answer = Option<Vec<u8>>;

fn pending() -> &'static Mutex<HashMap<u64, SyncSender<Answer>>> {
    static PENDING: OnceLock<Mutex<HashMap<u64, SyncSender<Answer>>>> = OnceLock::new();
    PENDING.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_id() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

/// One outstanding APDU exchange.
pub(crate) struct Exchange {
    id: u64,
    answers: Receiver<Answer>,
}

impl Exchange {
    /// Register an exchange and get the id the host will quote when answering.
    pub(crate) fn open() -> Self {
        let id = next_id();
        // Capacity one: the host answers exactly once, and a slot means it never
        // blocks doing so even if this side has already timed out and gone away.
        let (sender, answers) = sync_channel(1);

        pending()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, sender);

        Self { id, answers }
    }

    pub(crate) fn id(&self) -> u64 {
        self.id
    }

    /// Park until the host answers, or give up.
    pub(crate) fn wait(self) -> Result<Vec<u8>, String> {
        let outcome = self.answers.recv_timeout(EXCHANGE_TIMEOUT);

        // Whatever happened, this id is finished with.
        pending()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&self.id);

        match outcome {
            Ok(Some(response)) => Ok(response),
            Ok(None) => Err("the host reported that the exchange failed".to_string()),
            Err(_) => Err(format!(
                "the host did not answer within {}s",
                EXCHANGE_TIMEOUT.as_secs()
            )),
        }
    }
}

/// Deliver the host's answer. Returns false if the exchange is unknown — already
/// answered, or timed out and cleaned up.
pub(crate) fn supply(id: u64, answer: Answer) -> bool {
    let sender = pending()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&id);

    match sender {
        // A failed send means the waiter gave up first; the read is already unwinding.
        Some(sender) => sender.send(answer).is_ok(),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_answer_wakes_the_waiter() {
        let exchange = Exchange::open();
        let id = exchange.id();

        let waiter = std::thread::spawn(move || exchange.wait());
        // The host answers from another thread, as Dart's main isolate would.
        while !supply(id, Some(vec![0x90, 0x00])) {
            std::thread::yield_now();
        }

        assert_eq!(waiter.join().unwrap().unwrap(), vec![0x90, 0x00]);
    }

    #[test]
    fn a_reported_failure_reaches_the_waiter() {
        let exchange = Exchange::open();
        let id = exchange.id();

        let waiter = std::thread::spawn(move || exchange.wait());
        while !supply(id, None) {
            std::thread::yield_now();
        }

        assert!(waiter.join().unwrap().is_err());
    }

    #[test]
    fn answering_an_unknown_exchange_is_refused_rather_than_ignored() {
        assert!(!supply(u64::MAX, Some(vec![])));
    }

    #[test]
    fn an_exchange_is_answered_only_once() {
        let exchange = Exchange::open();
        let id = exchange.id();

        let waiter = std::thread::spawn(move || exchange.wait());
        while !supply(id, Some(vec![1])) {
            std::thread::yield_now();
        }
        waiter.join().unwrap().unwrap();

        // A duplicate answer — a double-tapped host callback — must not land on a
        // later exchange that happens to reuse the slot.
        assert!(!supply(id, Some(vec![2])));
    }
}
