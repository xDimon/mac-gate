//! Degradation is not a fall. The path to the server can rot - loss high
//! enough that no probe gets through - while the tunnel itself keeps
//! carrying. A reconnect does not mend a path, and it drops every
//! connection of the Mac at once, so a tunnel the peer still answers
//! through is left alone instead.
//!
//! Two pieces of evidence say the peer answers: the age of the handshake,
//! which is a full round trip and so cannot be faked by loss, and bytes
//! still coming in. Neither counts while the tunnel is young: raising one
//! is a handshake, and the answer to it lands in rx, so a flow cut at
//! birth would look alive by both. Too young, and only traffic through
//! the tunnel decides - which is what the checks do anyway.
//!
//! Patience with a degraded tunnel is a setting. When it runs out, one
//! reconnect - not the row of them a dead tunnel gets - and if that does
//! not help, the next wait is twice as long.

use std::time::{Duration, Instant};

/// Younger than this, and the tunnel says nothing about itself.
pub const YOUNG: Duration = Duration::from_secs(30);
/// A handshake no older than this proves the peer answered us just now:
/// the rekey interval fits into the window with room to spare.
const HANDSHAKE_FRESH: Duration = Duration::from_mins(3);
/// Reconnects that did not help grow the patience up to this many times
/// the setting.
const GROWTH: u32 = 8;
/// How long a degraded tunnel is left alone unless the settings say so.
pub const GRACE: Duration = Duration::from_mins(3);

/// Whether the tunnel itself says it still carries, while the probes
/// through it find nothing: `age` since the interface came up, `handshake`
/// seconds since the last handshake with the peer, and whether its bytes
/// are still coming.
pub fn carrying(age: Duration, handshake: Option<u64>, rx_grew: bool) -> bool {
    age >= YOUNG && rx_grew && handshake.is_some_and(|s| s <= HANDSHAKE_FRESH.as_secs())
}

/// How long the tunnel has been carrying undisturbed: the interface came
/// up at `up_at`, and a wake or a new network at `disturbed_at` makes it
/// as young as a freshly raised one - what it carried before them says
/// nothing about the path there is now.
pub fn age(up_at: Instant, disturbed_at: Instant, now: Instant) -> Duration {
    now.saturating_duration_since(up_at.max(disturbed_at))
}

/// What is done with a tunnel whose probes found nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Nothing says it carries: the usual repair.
    Down,
    /// Left alone, degraded for this long.
    Left(Duration),
    /// Out of patience: one reconnect.
    Restart,
}

/// The patience with a tunnel that carries while the probes fail.
#[derive(Clone, Copy, Debug)]
pub struct Degradation {
    /// The setting: zero is patience without end.
    grace: Duration,
    /// The patience now, grown by reconnects that did not help.
    patience: Duration,
    since: Option<Instant>,
}

impl Degradation {
    pub const fn new(grace: Duration) -> Self {
        Self {
            grace,
            patience: grace,
            since: None,
        }
    }

    /// How long the tunnel is left alone this time round.
    pub const fn patience(&self) -> Duration {
        self.patience
    }

    /// The probes found nothing; `carrying` is what the tunnel says of
    /// itself.
    pub fn failed(&mut self, now: Instant, carrying: bool) -> Verdict {
        if !carrying {
            // The clock stops, but not the grown patience: the check right
            // after a forced reconnect lands here, with the handshake not
            // back yet, and the wait must survive it.
            self.since = None;
            return Verdict::Down;
        }
        let since = *self.since.get_or_insert(now);
        let age = now.saturating_duration_since(since);
        if self.patience.is_zero() || age < self.patience {
            return Verdict::Left(age);
        }
        self.since = None;
        Verdict::Restart
    }

    /// The tunnel answers again: the patience is whole once more.
    pub fn passed(&mut self) {
        self.since = None;
        self.patience = self.grace;
    }

    /// The one reconnect did not help: the next wait is twice as long.
    pub fn harder(&mut self) {
        self.patience = (self.patience * 2).min(self.grace * GROWTH);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tunnel that is not fresh is checked this often.
    const STEP: Duration = Duration::from_secs(30);
    /// A reconnect, its confirmation, and the wait that lets the new
    /// tunnel out of the young window before it is checked again.
    const AFTER_RESTART: Duration = Duration::from_secs(40);

    #[test]
    fn both_pieces_of_evidence_are_needed() {
        let up = Duration::from_mins(10);
        assert!(carrying(up, Some(179), true));
        // A handshake that old is not an answer any more.
        assert!(!carrying(up, Some(181), true));
        // Nothing comes back, whatever the handshake says.
        assert!(!carrying(up, Some(10), false));
        // The peer has never answered at all.
        assert!(!carrying(up, None, true));
    }

    #[test]
    fn a_young_tunnel_says_nothing_about_itself() {
        // Raising a tunnel is a handshake, and the answer to it lands in
        // rx: a flow cut at birth looks alive by both.
        assert!(!carrying(Duration::from_secs(29), Some(0), true));
        assert!(carrying(YOUNG, Some(0), true));
    }

    #[test]
    fn a_woken_tunnel_is_young_again() {
        let now = Instant::now();
        let up = now.checked_sub(Duration::from_hours(1)).unwrap();
        // Undisturbed for an hour: the handshake and the bytes are
        // evidence.
        assert!(carrying(age(up, up, now), Some(10), true));
        // Woken, or moved to another network, five seconds ago: they are
        // not, and only traffic through the tunnel decides again.
        let disturbed = now.checked_sub(Duration::from_secs(5)).unwrap();
        assert!(!carrying(age(up, disturbed, now), Some(10), true));
        // The young window passes, and the tunnel speaks for itself again.
        let disturbed = now.checked_sub(YOUNG).unwrap();
        assert!(carrying(age(up, disturbed, now), Some(10), true));
    }

    #[test]
    fn a_tunnel_that_says_nothing_is_down_at_once() {
        let now = Instant::now();
        let mut d = Degradation::new(GRACE);
        for i in 0..10 {
            assert_eq!(d.failed(now + STEP * i, false), Verdict::Down);
        }
        assert_eq!(d.patience(), GRACE);
    }

    #[test]
    fn a_long_degradation_costs_units_of_reconnects() {
        // A rotten path under a tunnel long up, hour after hour: every
        // check finds the handshakes coming and rx growing, and no probe
        // gets through. Without the patience below, each of those checks
        // would cost a reconnect, and every session of the Mac with it.
        let start = Instant::now();
        let end = start + Duration::from_mins(85);
        let mut d = Degradation::new(GRACE);
        let mut at = start;
        let mut restarts = 0;
        let mut waits = Vec::new();
        while at < end {
            match d.failed(at, true) {
                Verdict::Left(_) => at += STEP,
                Verdict::Restart => {
                    restarts += 1;
                    waits.push(d.patience().as_secs());
                    // The path is still rotten, so it did not help.
                    d.harder();
                    at += AFTER_RESTART;
                }
                Verdict::Down => unreachable!("the tunnel carries"),
            }
        }
        assert_eq!(restarts, 5);
        assert_eq!(waits, vec![180, 360, 720, 1440, 1440]);
    }

    #[test]
    fn a_tunnel_that_answers_again_gets_its_patience_back() {
        let now = Instant::now();
        let mut d = Degradation::new(GRACE);
        assert_eq!(d.failed(now, true), Verdict::Left(Duration::ZERO));
        assert_eq!(d.failed(now + GRACE, true), Verdict::Restart);
        d.harder();
        assert_eq!(d.patience(), GRACE * 2);
        d.passed();
        assert_eq!(d.patience(), GRACE);
        // The clock starts anew as well: the whole grace is there to spend.
        let later = now + Duration::from_hours(1);
        assert_eq!(d.failed(later, true), Verdict::Left(Duration::ZERO));
        assert_eq!(d.failed(later + STEP, true), Verdict::Left(STEP));
        assert_eq!(d.failed(later + GRACE, true), Verdict::Restart);
    }

    #[test]
    fn patience_grows_eightfold_and_no_further() {
        let mut d = Degradation::new(GRACE);
        for _ in 0..10 {
            d.harder();
        }
        assert_eq!(d.patience(), GRACE * GROWTH);
    }

    #[test]
    fn zero_grace_never_runs_out() {
        let now = Instant::now();
        let mut d = Degradation::new(Duration::ZERO);
        assert_eq!(d.failed(now, true), Verdict::Left(Duration::ZERO));
        let day = Duration::from_hours(24);
        assert_eq!(d.failed(now + day, true), Verdict::Left(day));
        d.harder();
        assert_eq!(d.patience(), Duration::ZERO);
    }
}
