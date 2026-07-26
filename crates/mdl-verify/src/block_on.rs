//! A one-function executor.
//!
//! `isomdl`'s certificate-chain validator is `async` for one reason: it may fetch a
//! CRL over the network. This crate is no-network by design (like every other crate
//! in the workspace) and always passes the no-op revocation fetcher, so the future
//! completes on its first poll — it has nothing to await on.
//!
//! Rather than pull in a whole async runtime to call one function, drive it here with
//! a no-op waker. If the future ever does return `Pending` (which would mean upstream
//! grew a real suspension point on this path), we give up instead of spinning forever;
//! the caller turns that into [`crate::MdlError::ValidationDidNotComplete`].

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

/// Poll `fut` to completion, giving up after a handful of polls.
///
/// The bound is a backstop, not a real limit: on the paths this crate uses, the
/// future is ready on poll one.
pub(crate) fn try_block_on<F: Future>(fut: F) -> Option<F::Output> {
    const MAX_POLLS: usize = 64;

    let mut fut = pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());

    for _ in 0..MAX_POLLS {
        if let Poll::Ready(output) = fut.as_mut().poll(&mut cx) {
            return Some(output);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::try_block_on;

    #[test]
    fn completes_a_ready_future() {
        assert_eq!(try_block_on(async { 42 }), Some(42));
    }

    #[test]
    fn gives_up_on_a_future_that_never_completes() {
        let never =
            std::future::poll_fn(|_: &mut std::task::Context<'_>| std::task::Poll::<()>::Pending);
        assert_eq!(try_block_on(never), None);
    }
}
