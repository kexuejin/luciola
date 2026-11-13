//! Additive-increase / multiplicative-decrease window policy shared by both
//! UDP ARQ drivers (`adaptive`'s progressive driver and `udp::drive`).
//!
//! The direct path runs over consumer Wi-Fi, where a fixed in-flight budget
//! is provably wrong in both directions: too large and every ACK round dumps
//! a buffer-busting burst into the access point (measured: 93% of a flooded
//! 1200-byte stream never arrived); too small and a healthy path is capped
//! below its capacity. The window therefore starts small, grows with every
//! acknowledged byte (slow-start-style, roughly doubling per RTT), and halves
//! on every loss signal — fast retransmit or a timed resend.
//!
//! The window is enforced through the bridge's flow credit cap, so the
//! application writer is throttled by the same number the driver obeys; the
//! drivers never hold packets back in a second queue.

use super::bridge::MAX_UNACKED_BYTES;
use super::udp::MAX_PAYLOAD;

/// In-flight bytes when a direct path first carries data.
pub(crate) const INITIAL_WINDOW: usize = 16 * 1024;
/// Floor after repeated losses: low enough to drain a lossy link, high
/// enough that one RTT still moves real data (~0.5 MB/s at 30 ms).
pub(crate) const MIN_WINDOW: usize = 16 * 1024;

#[derive(Clone, Copy)]
pub(crate) struct AimdWindow {
    window: usize,
}

impl AimdWindow {
    pub(crate) fn new() -> Self {
        Self {
            window: INITIAL_WINDOW,
        }
    }

    pub(crate) fn value(&self) -> usize {
        self.window
    }

    /// Acknowledged bytes free room: grow by at least one segment so a
    /// trickle of small ACKs still opens the window over time.
    pub(crate) fn on_progress(&mut self, freed: usize) {
        self.window = (self.window + freed.max(MAX_PAYLOAD)).min(MAX_UNACKED_BYTES);
    }

    /// Any loss signal halves the window; repeated signals keep halving
    /// until the floor.
    pub(crate) fn on_loss(&mut self) {
        self.window = (self.window / 2).max(MIN_WINDOW);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grows_on_progress_and_caps_at_the_bridge_ceiling() {
        let mut w = AimdWindow::new();
        assert_eq!(w.value(), INITIAL_WINDOW);
        w.on_progress(INITIAL_WINDOW);
        assert_eq!(w.value(), INITIAL_WINDOW * 2);
        for _ in 0..20 {
            w.on_progress(INITIAL_WINDOW);
        }
        assert_eq!(w.value(), MAX_UNACKED_BYTES);
        // A tiny ACK still opens the window by at least one segment.
        let mut w2 = AimdWindow::new();
        w2.on_progress(0);
        assert_eq!(w2.value(), INITIAL_WINDOW + MAX_PAYLOAD);
    }

    #[test]
    fn halves_on_loss_but_never_below_the_floor() {
        let mut w = AimdWindow::new();
        for _ in 0..20 {
            w.on_progress(MAX_PAYLOAD);
        }
        let peak = w.value();
        w.on_loss();
        assert_eq!(w.value(), peak / 2);
        for _ in 0..20 {
            w.on_loss();
        }
        assert_eq!(w.value(), MIN_WINDOW);
    }
}
