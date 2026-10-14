//! Policy for manual connectors that hold their link only while it is needed.
//!
//! An on-demand link is needed while
//! - its peer is unknown or cannot be reached through the rest of the network
//!   (bootstrap and fallback), or
//! - a peer this node exchanges data with gets a clearly lower latency-first path
//!   cost through the link, for example after hole punching to that peer failed.
//!
//! Once neither holds, the link is closed after a randomized hold-down, so idle
//! nodes keep no direct traffic, heartbeats included, with the linked peer. Every
//! evaluation compares path costs with and without the link, using the latency
//! measured on the link while it is up and the last measurement while it is down.

use std::{
    collections::{BTreeMap, HashMap},
    time::Duration,
};

use quanta::Instant;
use rand::Rng;
use serde::{Deserialize, Serialize};

use crate::config::PeerId;

/// A peer counts as exchanging data with this node for this long after its last packet.
pub(crate) const ACTIVITY_TTL: Duration = Duration::from_secs(30);
const RETRY_BACKOFF_SECS: [u64; 7] = [1, 2, 4, 8, 16, 30, 60];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OnDemandOptions {
    /// Time a destination has to have been active before the link is opened for it,
    /// which leaves hole punching a chance to connect it directly first.
    pub relay_grace: Duration,
    /// An opened link stays up at least this long, so its latency gets measured.
    pub min_connected: Duration,
    /// An unneeded link is closed after a hold-down drawn from this range. The
    /// jitter keeps several on-demand nodes sharing a relay from dropping it at once.
    pub idle_hold_min: Duration,
    pub idle_hold_max: Duration,
    /// How long a link latency measured earlier is trusted while the link is down.
    pub latency_cache_ttl: Duration,
    /// Minimum time between links opened only to measure their latency.
    pub probe_interval: Duration,
}

impl Default for OnDemandOptions {
    fn default() -> Self {
        Self {
            relay_grace: Duration::from_secs(10),
            min_connected: Duration::from_secs(15),
            idle_hold_min: Duration::from_secs(60),
            idle_hold_max: Duration::from_secs(120),
            latency_cache_ttl: Duration::from_secs(30 * 60),
            probe_interval: Duration::from_secs(10 * 60),
        }
    }
}

impl OnDemandOptions {
    fn sample_idle_hold(&self) -> Duration {
        if self.idle_hold_max <= self.idle_hold_min {
            return self.idle_hold_min;
        }
        rand::thread_rng().gen_range(self.idle_hold_min..=self.idle_hold_max)
    }
}

/// Smallest latency improvement that justifies a link, in milliseconds and as a
/// percentage of the path cost without it. Keeping uses a lower bar than opening so
/// the decision does not flap around the threshold.
#[derive(Debug, Clone, Copy)]
struct LatencyGain {
    min_ms: usize,
    min_percent: usize,
}

const CONNECT_GAIN: LatencyGain = LatencyGain {
    min_ms: 10,
    min_percent: 10,
};
const KEEP_GAIN: LatencyGain = LatencyGain {
    min_ms: 5,
    min_percent: 5,
};

impl LatencyGain {
    fn improves(self, without_link: Option<usize>, with_link: Option<usize>) -> bool {
        let Some(with_link) = with_link else {
            return false;
        };
        let Some(without_link) = without_link else {
            // only reachable through the link
            return true;
        };
        let gain = without_link.saturating_sub(with_link);
        gain > 0 && gain >= self.min_ms && gain * 100 >= without_link * self.min_percent
    }
}

/// The link latency an evaluation uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LinkEstimate {
    /// Measured on the live link.
    Measured(i32),
    /// Measured the last time the link was up.
    Cached(i32),
    /// Nothing measured yet, or the measurement is stale. Evaluated optimistically
    /// as a zero-latency link, which bounds what the link could gain.
    Unknown,
}

impl LinkEstimate {
    pub(crate) fn cost(self) -> i32 {
        match self {
            LinkEstimate::Measured(ms) | LinkEstimate::Cached(ms) => ms,
            LinkEstimate::Unknown => 0,
        }
    }
}

/// Latency-first path costs to one destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DestinationCosts {
    pub without_link: Option<usize>,
    pub with_link: Option<usize>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OnDemandInput {
    pub alive: bool,
    /// The link's peer is reachable without the link.
    pub peer_reachable_elsewhere: bool,
    /// The estimate `with_link` costs were computed with.
    pub estimate: LinkEstimate,
    /// Peers exchanging data with this node, other than the link's peer.
    pub destinations: BTreeMap<PeerId, DestinationCosts>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnDemandNeed {
    /// The link's peer is unknown or otherwise unreachable.
    Bootstrap,
    /// The destination gets a lower latency through the link.
    Latency(PeerId),
    /// The destination might get a lower latency through the link, whose latency
    /// has to be measured first.
    Probe(PeerId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OnDemandAction {
    None,
    Connect(OnDemandNeed),
    Disconnect,
}

#[derive(Debug)]
pub(crate) struct OnDemandLink {
    options: OnDemandOptions,
    peer_id: Option<PeerId>,
    connecting: bool,
    connected_at: Option<Instant>,
    idle_since: Option<Instant>,
    idle_hold: Duration,
    // the live link was opened as a probe and has not been needed since
    probing: bool,
    link_latency: Option<(i32, Instant)>,
    last_probe_at: Option<Instant>,
    active_since: HashMap<PeerId, Instant>,
    retry_at: Option<Instant>,
    failures: usize,
}

impl OnDemandLink {
    pub(crate) fn new(options: OnDemandOptions) -> Self {
        Self {
            options,
            peer_id: None,
            connecting: false,
            connected_at: None,
            idle_since: None,
            idle_hold: Duration::ZERO,
            probing: false,
            link_latency: None,
            last_probe_at: None,
            active_since: HashMap::new(),
            retry_at: None,
            failures: 0,
        }
    }

    pub(crate) fn peer_id(&self) -> Option<PeerId> {
        self.peer_id
    }

    pub(crate) fn is_connecting(&self) -> bool {
        self.connecting
    }

    /// Forgets an attempt that was aborted before reporting its result.
    pub(crate) fn cancel_connect(&mut self) {
        self.connecting = false;
    }

    /// The link latency to evaluate with: measured on the live link, otherwise the
    /// last measurement while it is fresh.
    pub(crate) fn estimate(
        &self,
        now: Instant,
        alive: bool,
        measured_ms: Option<i32>,
    ) -> LinkEstimate {
        if alive {
            return measured_ms.map_or(LinkEstimate::Unknown, LinkEstimate::Measured);
        }
        match self.link_latency {
            Some((ms, at))
                if now.saturating_duration_since(at) <= self.options.latency_cache_ttl =>
            {
                LinkEstimate::Cached(ms)
            }
            _ => LinkEstimate::Unknown,
        }
    }

    pub(crate) fn step(&mut self, now: Instant, input: &OnDemandInput) -> OnDemandAction {
        self.active_since
            .retain(|peer_id, _| input.destinations.contains_key(peer_id));
        for peer_id in input.destinations.keys() {
            self.active_since.entry(*peer_id).or_insert(now);
        }
        if let LinkEstimate::Measured(ms) = input.estimate {
            self.link_latency = Some((ms, now));
        }

        let need = self.need(now, input);
        if input.alive {
            return self.step_connected(now, need);
        }

        self.connected_at = None;
        self.idle_since = None;
        let Some(need) = need else {
            return OnDemandAction::None;
        };
        if self.connecting || self.retry_at.is_some_and(|retry_at| now < retry_at) {
            return OnDemandAction::None;
        }
        self.probing = matches!(need, OnDemandNeed::Probe(_));
        if self.probing {
            self.last_probe_at = Some(now);
        }
        self.connecting = true;
        OnDemandAction::Connect(need)
    }

    fn step_connected(&mut self, now: Instant, need: Option<OnDemandNeed>) -> OnDemandAction {
        let connected_at = *self.connected_at.get_or_insert(now);
        if need.is_some() {
            self.idle_since = None;
            self.probing = false;
            return OnDemandAction::None;
        }

        let idle_since = match self.idle_since {
            Some(idle_since) => idle_since,
            None => {
                // a probe that found no gain is closed as soon as it was measured
                self.idle_hold = if self.probing {
                    Duration::ZERO
                } else {
                    self.options.sample_idle_hold()
                };
                self.idle_since = Some(now);
                now
            }
        };
        if now.saturating_duration_since(connected_at) < self.options.min_connected
            || now.saturating_duration_since(idle_since) < self.idle_hold
        {
            return OnDemandAction::None;
        }

        self.connected_at = None;
        self.idle_since = None;
        self.probing = false;
        OnDemandAction::Disconnect
    }

    fn need(&self, now: Instant, input: &OnDemandInput) -> Option<OnDemandNeed> {
        if self.peer_id.is_none() || !input.peer_reachable_elsewhere {
            return Some(OnDemandNeed::Bootstrap);
        }

        let gain = if input.alive { KEEP_GAIN } else { CONNECT_GAIN };
        let destination = input
            .destinations
            .iter()
            .filter(|(peer_id, _)| {
                input.alive
                    || self.active_since.get(peer_id).is_some_and(|since| {
                        now.saturating_duration_since(*since) >= self.options.relay_grace
                    })
            })
            .find(|(_, costs)| gain.improves(costs.without_link, costs.with_link))
            .map(|(peer_id, _)| *peer_id)?;

        match input.estimate {
            LinkEstimate::Measured(_) | LinkEstimate::Cached(_) => {
                Some(OnDemandNeed::Latency(destination))
            }
            // the live link has no latency sample yet
            LinkEstimate::Unknown if input.alive => Some(OnDemandNeed::Latency(destination)),
            LinkEstimate::Unknown => self
                .last_probe_at
                .is_none_or(|at| now.saturating_duration_since(at) >= self.options.probe_interval)
                .then_some(OnDemandNeed::Probe(destination)),
        }
    }

    /// Records a finished connect attempt. Returns the previously known peer id when
    /// the link now leads to a different peer.
    pub(crate) fn on_connect_result(
        &mut self,
        now: Instant,
        result: Result<PeerId, ()>,
    ) -> Option<PeerId> {
        self.connecting = false;
        match result {
            Ok(peer_id) => {
                self.failures = 0;
                self.retry_at = None;
                self.peer_id
                    .replace(peer_id)
                    .filter(|previous| *previous != peer_id)
            }
            Err(()) => {
                let backoff = RETRY_BACKOFF_SECS[self.failures.min(RETRY_BACKOFF_SECS.len() - 1)];
                self.failures += 1;
                self.retry_at = Some(now + Duration::from_secs(backoff));
                None
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const LINK_PEER: PeerId = 100;
    const DST: PeerId = 7;

    fn options() -> OnDemandOptions {
        OnDemandOptions::default()
    }

    fn input(
        alive: bool,
        estimate: LinkEstimate,
        destinations: impl IntoIterator<Item = (PeerId, Option<usize>, Option<usize>)>,
    ) -> OnDemandInput {
        OnDemandInput {
            alive,
            peer_reachable_elsewhere: true,
            estimate,
            destinations: destinations
                .into_iter()
                .map(|(peer_id, without_link, with_link)| {
                    (
                        peer_id,
                        DestinationCosts {
                            without_link,
                            with_link,
                        },
                    )
                })
                .collect(),
        }
    }

    fn idle(alive: bool) -> OnDemandInput {
        input(alive, LinkEstimate::Measured(20), [])
    }

    /// A link that bootstrapped and is now up.
    fn connected_link(now: Instant) -> OnDemandLink {
        let mut link = OnDemandLink::new(options());
        assert_eq!(
            link.step(now, &idle(false)),
            OnDemandAction::Connect(OnDemandNeed::Bootstrap)
        );
        assert_eq!(link.on_connect_result(now, Ok(LINK_PEER)), None);
        link
    }

    fn run_until_disconnect(
        link: &mut OnDemandLink,
        start: Instant,
        input: &OnDemandInput,
    ) -> Duration {
        for secs in 0..=600 {
            let elapsed = Duration::from_secs(secs);
            if link.step(start + elapsed, input) == OnDemandAction::Disconnect {
                return elapsed;
            }
        }
        panic!("link was never disconnected");
    }

    #[test]
    fn latency_gain_needs_absolute_and_relative_improvement() {
        assert!(CONNECT_GAIN.improves(Some(100), Some(80)));
        assert!(!CONNECT_GAIN.improves(Some(100), Some(95)));
        // 15ms out of 1000ms is under 10%
        assert!(!CONNECT_GAIN.improves(Some(1000), Some(985)));
        // 8ms out of 40ms is 20% but under 10ms
        assert!(!CONNECT_GAIN.improves(Some(40), Some(32)));
        assert!(CONNECT_GAIN.improves(None, Some(500)));
        assert!(!CONNECT_GAIN.improves(Some(10), None));
        assert!(!CONNECT_GAIN.improves(Some(10), Some(20)));
        assert!(KEEP_GAIN.improves(Some(100), Some(94)));
    }

    #[test]
    fn unknown_peer_bootstraps_and_retries_with_backoff() {
        let now = Instant::now();
        let mut link = OnDemandLink::new(options());
        assert_eq!(
            link.step(now, &idle(false)),
            OnDemandAction::Connect(OnDemandNeed::Bootstrap)
        );
        // one attempt at a time
        assert_eq!(link.step(now, &idle(false)), OnDemandAction::None);

        link.on_connect_result(now, Err(()));
        assert_eq!(link.step(now, &idle(false)), OnDemandAction::None);
        let retry = now + Duration::from_secs(1);
        assert_eq!(
            link.step(retry, &idle(false)),
            OnDemandAction::Connect(OnDemandNeed::Bootstrap)
        );
        link.on_connect_result(retry, Err(()));
        assert_eq!(
            link.step(retry + Duration::from_secs(1), &idle(false)),
            OnDemandAction::None
        );
        assert_eq!(
            link.step(retry + Duration::from_secs(2), &idle(false)),
            OnDemandAction::Connect(OnDemandNeed::Bootstrap)
        );
    }

    #[test]
    fn idle_link_is_closed_after_hold_down_and_reopened_when_peer_is_isolated() {
        let now = Instant::now();
        let mut link = connected_link(now);

        let elapsed = run_until_disconnect(&mut link, now, &idle(true));
        assert!(
            (options().idle_hold_min..=options().idle_hold_max).contains(&elapsed),
            "{elapsed:?}"
        );

        let later = now + elapsed + Duration::from_secs(1);
        assert_eq!(link.step(later, &idle(false)), OnDemandAction::None);

        let mut isolated = idle(false);
        isolated.peer_reachable_elsewhere = false;
        assert_eq!(
            link.step(later, &isolated),
            OnDemandAction::Connect(OnDemandNeed::Bootstrap)
        );
    }

    #[test]
    fn link_stays_while_peer_is_only_reachable_through_it() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let mut isolated = idle(true);
        isolated.peer_reachable_elsewhere = false;
        for secs in 0..600 {
            assert_eq!(
                link.step(now + Duration::from_secs(secs), &isolated),
                OnDemandAction::None
            );
        }
    }

    #[test]
    fn relayed_destination_reopens_link_after_grace_when_latency_is_lower() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let elapsed = run_until_disconnect(&mut link, now, &idle(true));
        let down = now + elapsed;

        // hole punching to DST failed: 120ms over the relay, 40ms through the link
        let relayed = input(
            false,
            LinkEstimate::Cached(20),
            [(DST, Some(120), Some(40))],
        );
        assert_eq!(link.step(down, &relayed), OnDemandAction::None);
        assert_eq!(
            link.step(
                down + options().relay_grace - Duration::from_secs(1),
                &relayed
            ),
            OnDemandAction::None
        );
        assert_eq!(
            link.step(down + options().relay_grace, &relayed),
            OnDemandAction::Connect(OnDemandNeed::Latency(DST))
        );
    }

    #[test]
    fn longer_but_faster_path_keeps_link_closed() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let elapsed = run_until_disconnect(&mut link, now, &idle(true));
        let down = now + elapsed;

        // the current multi-hop path is faster than the link would be
        let slower_link = input(false, LinkEstimate::Cached(80), [(DST, Some(60), Some(95))]);
        for secs in 0..120 {
            assert_eq!(
                link.step(down + Duration::from_secs(secs), &slower_link),
                OnDemandAction::None
            );
        }
    }

    #[test]
    fn link_closes_once_destination_goes_direct_or_away() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let relayed = input(
            true,
            LinkEstimate::Measured(20),
            [(DST, Some(120), Some(40))],
        );
        for secs in 0..300 {
            assert_eq!(
                link.step(now + Duration::from_secs(secs), &relayed),
                OnDemandAction::None
            );
        }

        // hole punching succeeded: the direct path beats the link
        let start = now + Duration::from_secs(300);
        let direct = input(
            true,
            LinkEstimate::Measured(20),
            [(DST, Some(30), Some(30))],
        );
        let elapsed = run_until_disconnect(&mut link, start, &direct);
        assert!(elapsed >= options().idle_hold_min);

        // DST going offline ends its activity, which equally lets the link go
        let mut link = connected_link(now);
        assert!(run_until_disconnect(&mut link, now, &idle(true)) >= options().min_connected);
    }

    #[test]
    fn unknown_link_latency_is_probed_and_closed_quickly_without_gain() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let elapsed = run_until_disconnect(&mut link, now, &idle(true));
        let down = now + elapsed + options().latency_cache_ttl + Duration::from_secs(1);

        // with a zero-latency link DST would go from 120ms to 40ms
        let optimistic = input(false, LinkEstimate::Unknown, [(DST, Some(120), Some(40))]);
        assert_eq!(link.step(down, &optimistic), OnDemandAction::None);
        let probe_at = down + options().relay_grace;
        assert_eq!(
            link.step(probe_at, &optimistic),
            OnDemandAction::Connect(OnDemandNeed::Probe(DST))
        );
        link.on_connect_result(probe_at, Ok(LINK_PEER));

        // measured 150ms: no gain, so the probe closes once its minimum time is up
        let measured = input(
            true,
            LinkEstimate::Measured(150),
            [(DST, Some(120), Some(230))],
        );
        assert_eq!(
            run_until_disconnect(&mut link, probe_at, &measured),
            options().min_connected
        );

        // the fresh measurement now rules out the link without another probe
        let down = probe_at + options().min_connected + Duration::from_secs(1);
        let cached = input(
            false,
            link.estimate(down, false, None),
            [(DST, Some(120), Some(230))],
        );
        assert_eq!(cached.estimate, LinkEstimate::Cached(150));
        for secs in 0..60 {
            assert_eq!(
                link.step(down + Duration::from_secs(secs), &cached),
                OnDemandAction::None
            );
        }
    }

    #[test]
    fn probes_are_rate_limited() {
        let now = Instant::now();
        let mut link = connected_link(now);
        let elapsed = run_until_disconnect(&mut link, now, &idle(true));
        let down = now + elapsed + options().latency_cache_ttl + Duration::from_secs(1);

        let optimistic = input(false, LinkEstimate::Unknown, [(DST, Some(120), Some(40))]);
        link.step(down, &optimistic);
        let probe_at = down + options().relay_grace;
        assert_eq!(
            link.step(probe_at, &optimistic),
            OnDemandAction::Connect(OnDemandNeed::Probe(DST))
        );
        link.on_connect_result(probe_at, Err(()));

        for secs in 1..options().probe_interval.as_secs() {
            assert_eq!(
                link.step(probe_at + Duration::from_secs(secs), &optimistic),
                OnDemandAction::None
            );
        }
        assert_eq!(
            link.step(probe_at + options().probe_interval, &optimistic),
            OnDemandAction::Connect(OnDemandNeed::Probe(DST))
        );
    }

    #[test]
    fn connect_result_reports_changed_peer_id() {
        let now = Instant::now();
        let mut link = OnDemandLink::new(options());
        assert_eq!(link.on_connect_result(now, Ok(1)), None);
        assert_eq!(link.on_connect_result(now, Ok(1)), None);
        assert_eq!(link.on_connect_result(now, Ok(2)), Some(1));
        assert_eq!(link.peer_id(), Some(2));
    }
}
