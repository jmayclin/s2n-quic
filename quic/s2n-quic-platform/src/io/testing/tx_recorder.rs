use super::network::{Buffers, Network, Packet};
use core::time::Duration;
use s2n_quic_core::{havoc, path::MaxMtu};
use std::{
    borrow::Cow,
    sync::{
        atomic::{AtomicU16, AtomicU64, Ordering},
        Arc,
    },
};

