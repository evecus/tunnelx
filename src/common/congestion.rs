//! QUIC congestion control selection (bbr | brutal | cubic).
//!
//! - `bbr`   → quinn's built-in experimental BBR (`quinn::congestion::BbrConfig`)
//! - `cubic` → quinn's default (loss-based, RFC 9438)
//! - `brutal`→ fixed-bandwidth-hint controller (hysteria-style), implemented on
//!   top of the `brutal-core` crate and wrapped into quinn's `Controller` trait
//!   by [`BrutalController`].

use std::any::Any;
use std::sync::Arc;

use anyhow::{bail, Result};
use brutal_core::{BrutalConfigCore, BrutalCore};
use quinn_proto::RttEstimator;

/// Selected QUIC congestion control algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Congestion {
    /// BBR (quinn built-in, experimental): bandwidth/RTT model based, robust on lossy links.
    Bbr,
    /// Brutal: target a fixed bandwidth regardless of loss. Requires `brutal_mbps > 0`.
    Brutal { bandwidth_mbps: u64 },
    /// Cubic (quinn default): loss-based, safe but throttles hard on lossy links.
    Cubic,
}

impl Congestion {
    /// Parse from config string. `brutal_mbps` is only used when `algorithm == "brutal"`.
    pub fn parse(algorithm: &str, brutal_mbps: u64) -> Result<Self> {
        match algorithm {
            "bbr" => Ok(Self::Bbr),
            "cubic" => Ok(Self::Cubic),
            "brutal" => {
                if brutal_mbps == 0 {
                    bail!("congestion.brutal_mbps must be > 0 when congestion.algorithm = \"brutal\"");
                }
                Ok(Self::Brutal { bandwidth_mbps: brutal_mbps })
            }
            other => bail!(
                "unknown congestion.algorithm \"{other}\" (expected bbr | brutal | cubic)"
            ),
        }
    }

    /// Build the quinn controller factory for this algorithm.
    pub fn controller_factory(
        self,
    ) -> Arc<dyn quinn::congestion::ControllerFactory + Send + Sync> {
        match self {
            Self::Bbr => Arc::new(quinn::congestion::BbrConfig::default()),
            Self::Cubic => Arc::new(quinn::congestion::CubicConfig::default()),
            Self::Brutal { bandwidth_mbps } => Arc::new(BrutalFactory {
                bandwidth_bps: bandwidth_mbps.saturating_mul(1_000_000),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Brutal → quinn adapter
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct BrutalFactory {
    bandwidth_bps: u64,
}

impl quinn::congestion::ControllerFactory for BrutalFactory {
    fn build(
        self: Arc<Self>,
        now: std::time::Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        let config = BrutalConfigCore {
            default_bandwidth_bps: self.bandwidth_bps,
            ..Default::default()
        };
        Box::new(BrutalController {
            core: BrutalCore::new(config, now, current_mtu),
        })
    }
}

#[derive(Debug, Clone)]
struct BrutalController {
    core: BrutalCore,
}

impl quinn::congestion::Controller for BrutalController {
    fn on_sent(&mut self, _now: std::time::Instant, bytes: u64, _last_packet_number: u64) {
        self.core.on_sent(bytes);
    }

    fn on_ack(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.core.on_ack_bytes(bytes, rtt.get());
    }

    fn on_end_acks(
        &mut self,
        now: std::time::Instant,
        _in_flight: u64,
        _app_limited: bool,
        _largest_packet_num_acked: Option<u64>,
    ) {
        self.core.on_end_acks(now);
    }

    fn on_congestion_event(
        &mut self,
        _now: std::time::Instant,
        _sent: std::time::Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        // Brutal does not back off on loss; it only uses it for ack-rate estimation.
        self.core.on_loss_bytes(lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.core.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        self.core.window_cached()
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.core.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}
