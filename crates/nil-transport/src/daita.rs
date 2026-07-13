//! Maybenot / DAITA traffic-analysis defense driver — experimental, behind the `daita` feature.
//!
//! A structurally-oblivious multi-hop VPN still leaks a *timing/volume* fingerprint to a local or
//! on-path adversary (website fingerprinting, flow correlation — inside NIL's threat model, unlike
//! the excluded global passive adversary). Mullvad's answer is DAITA: drive probabilistic
//! [`maybenot`] state machines that inject cover padding (and, later, blocking) to reshape the
//! trace. This module is the *driver*: it feeds real packet **events** into a [`Framework`], reads
//! the **actions** it emits, and turns each `SendPadding` into a cover-traffic datagram on the
//! CONNECT-IP padding channel already shipped ([`crate::connectip::encode_padding_datagram`],
//! `context_id = 1`, which both peers discard). The framework only DECIDES *what/when*; this driver
//! SCHEDULES and hands back what to send.
//!
//! ## Scope (deliberate)
//! - **Padding only for now.** `BlockOutgoing`/`UpdateTimer`/`Cancel` actions are parsed but not yet
//!   enacted (blocking delays real packets — a bigger datapath change). Padding is the safe subset:
//!   it never holds a user packet back.
//! - **The driver is engine-only + tested here; live datapath wiring is gated behind `daita` and
//!   off by default.** The action-scheduling logic below is deterministically unit-tested, but
//!   whether a given defense actually *helps* is a separate question:
//! - **Machine selection + efficacy are NOT decided here.** Which defense machines to run (and
//!   proving they degrade a real classifier) is a research step, done offline with
//!   `maybenot-simulator` against website-fingerprinting traces. This driver runs whatever machines
//!   that step selects — it is the mechanism, not the policy. Keeping it optional and tunable (not
//!   default cover traffic) is intentional: constant cover trades latency for a threat PD-8 already
//!   disclaims.
//!
//! PD-3: nothing here logs an address, a payload, or a destination — only, at most, opaque counts.

use std::time::Instant;

use maybenot::{Framework, Machine, MachineId, TriggerAction, TriggerEvent};
use rand_core::RngCore;

/// A cover-traffic padding datagram the datapath should emit *now*. By the time the driver returns
/// one it has already re-notified the framework that the padding was sent, so the caller only has to
/// write `len` bytes of padding on the padding channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PaddingSend {
    /// The machine that scheduled it — diagnostics only (never logged with any address; PD-3).
    pub machine: usize,
    /// Padding payload length in bytes; the datapath caps it to the negotiated tunnel MTU.
    pub len: usize,
}

/// One padding action awaiting its deadline. At most one is kept per machine — a fresh `SendPadding`
/// replaces any still-pending one for that machine, matching maybenot's "one action timer per
/// machine" contract.
struct Pending {
    deadline: Instant,
    machine: MachineId,
}

/// Drives a [`maybenot::Framework`] from packet events to scheduled padding sends. Generic over the
/// RNG the framework samples its distributions with (a real deployment passes an OS RNG; tests pass
/// a seeded one for determinism).
pub struct DaitaDriver<R: RngCore> {
    framework: Framework<Vec<Machine>, R>,
    pending: Vec<Pending>,
    /// Fixed cover-packet size. A constant, MTU-shaped padding datagram is the conservative default;
    /// a size-sampling profile is a later tuning knob.
    pad_len: usize,
}

impl<R: RngCore> DaitaDriver<R> {
    /// Build a driver running `machines`, starting its clock at `now`. Padding-only: the framework's
    /// padding fraction is unconstrained (per-machine `allowed_padding_packets` still bounds it) and
    /// its blocking fraction is zero, since this driver does not enact blocking yet.
    pub fn new(machines: Vec<Machine>, now: Instant, rng: R) -> Result<Self, maybenot::Error> {
        let framework = Framework::new(machines, 1.0, 0.0, now, rng)?;
        Ok(Self {
            framework,
            pending: Vec::new(),
            pad_len: 1200,
        })
    }

    /// Feed real packet events (e.g. [`TriggerEvent::NormalSent`] on a data-plane send,
    /// [`TriggerEvent::NormalRecv`] on a receive) and schedule any padding the machines decide on.
    pub fn on_events(&mut self, events: &[TriggerEvent], now: Instant) {
        self.drive(events, now);
    }

    /// Run the framework over `events` and (re)schedule the resulting padding actions.
    fn drive(&mut self, events: &[TriggerEvent], now: Instant) {
        // Collect first so the framework borrow ends before we mutate `pending`.
        let scheduled: Vec<(Instant, MachineId)> = self
            .framework
            .trigger_events(events, now)
            .filter_map(|action| match action {
                TriggerAction::SendPadding {
                    timeout, machine, ..
                } => {
                    // Saturate rather than panic if now + timeout overflows the Instant domain.
                    Some((now.checked_add(*timeout).unwrap_or(now), *machine))
                }
                // Blocking / timer / cancel actions are not enacted yet (padding-only; see module doc).
                _ => None,
            })
            .collect();
        for (deadline, machine) in scheduled {
            self.pending.retain(|p| p.machine != machine); // one pending action per machine
            self.pending.push(Pending { deadline, machine });
        }
    }

    /// The earliest scheduled padding deadline, for the caller to arm a timer against. `None` when
    /// nothing is pending.
    pub fn next_deadline(&self) -> Option<Instant> {
        self.pending.iter().map(|p| p.deadline).min()
    }

    /// Emit every padding action whose deadline is at or before `now`, re-notifying the framework of
    /// each `PaddingSent` (which may schedule follow-on actions). Returns the datagrams to send.
    pub fn poll(&mut self, now: Instant) -> Vec<PaddingSend> {
        let mut due: Vec<MachineId> = Vec::new();
        self.pending.retain(|p| {
            let fire = p.deadline <= now;
            if fire {
                due.push(p.machine);
            }
            !fire
        });
        let mut sends = Vec::with_capacity(due.len());
        for machine in due {
            sends.push(PaddingSend {
                machine: machine.into_raw(),
                len: self.pad_len,
            });
            // The padding is now queued: tell the framework, so a machine can advance / repeat.
            self.drive(&[TriggerEvent::PaddingSent { machine }], now);
        }
        sends
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use enum_map::enum_map;
    use maybenot::action::Action;
    use maybenot::dist::{Dist, DistType};
    use maybenot::event::Event;
    use maybenot::state::{State, Trans};
    use rand::SeedableRng;

    use super::*;

    /// A constant (deterministic) distribution — maybenot samples a constant when `low == high`.
    fn constant(v: f64) -> Dist {
        Dist {
            dist: DistType::Uniform { low: v, high: v },
            start: 0.0,
            max: 0.0,
        }
    }

    /// Machine: on the first `NormalSent`, move to a terminal state that pads once, 10 ms later.
    fn pad_once_machine() -> Machine {
        let s0 = State::new(enum_map! {
            Event::NormalSent => vec![Trans(1, 1.0)],
            _ => vec![],
        });
        let mut s1 = State::new(enum_map! { _ => vec![] });
        s1.action = Some(Action::SendPadding {
            bypass: false,
            replace: false,
            timeout: constant(10_000.0), // sample is microseconds ⇒ 10 ms
            limit: None,
        });
        // allowed_padding_packets=100, max_padding_frac=1.0, no blocking.
        Machine::new(100, 1.0, 0, 0.0, vec![s0, s1]).expect("valid machine")
    }

    fn driver_at(t0: Instant, seed: u8) -> DaitaDriver<rand::rngs::StdRng> {
        let rng = rand::rngs::StdRng::from_seed([seed; 32]);
        DaitaDriver::new(vec![pad_once_machine()], t0, rng).expect("framework builds")
    }

    #[test]
    fn schedules_padding_after_normal_sent_and_fires_once() {
        let t0 = Instant::now();
        let mut d = driver_at(t0, 7);

        // Nothing sent yet ⇒ nothing scheduled, nothing due.
        assert!(d.next_deadline().is_none());
        assert!(d.poll(t0).is_empty());

        // A real packet went out ⇒ the machine schedules exactly one future padding.
        d.on_events(&[TriggerEvent::NormalSent], t0);
        let deadline = d.next_deadline().expect("a padding action is scheduled");
        assert!(
            deadline > t0,
            "padding is scheduled in the future, not immediately"
        );

        // Not due yet ⇒ no send.
        assert!(d.poll(t0).is_empty());

        // Due ⇒ exactly one padding datagram, attributed to machine 0, with a non-empty length.
        let sends = d.poll(deadline);
        assert_eq!(sends.len(), 1, "one padding datagram becomes due");
        assert_eq!(sends[0].machine, 0);
        assert!(sends[0].len > 0);

        // Single-fire machine: nothing pending afterwards, and later polls stay empty.
        assert!(
            d.next_deadline().is_none(),
            "no further padding after the single fire"
        );
        assert!(d.poll(deadline + Duration::from_secs(1)).is_empty());
    }

    #[test]
    fn unrelated_event_triggers_no_padding() {
        // This machine only reacts to NormalSent; a NormalRecv must not schedule padding.
        let t0 = Instant::now();
        let mut d = driver_at(t0, 9);
        d.on_events(&[TriggerEvent::NormalRecv], t0);
        assert!(d.next_deadline().is_none());
        assert!(d.poll(t0 + Duration::from_secs(1)).is_empty());
    }
}
