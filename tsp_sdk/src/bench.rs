use crate::BenchNetworkTimings;
use std::{
    collections::HashMap,
    sync::{Mutex, OnceLock},
    thread::ThreadId,
    time::Instant,
};

struct BenchCollector {
    per_thread: Mutex<HashMap<ThreadId, BenchNetworkTimings>>,
}

impl BenchCollector {
    fn global() -> &'static Self {
        static GLOBAL: OnceLock<BenchCollector> = OnceLock::new();
        GLOBAL.get_or_init(|| BenchCollector {
            per_thread: Mutex::new(HashMap::new()),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<ThreadId, BenchNetworkTimings>> {
        self.per_thread
            .lock()
            .unwrap_or_else(|err| err.into_inner())
    }

    fn reset_current(&self) {
        self.lock()
            .insert(std::thread::current().id(), BenchNetworkTimings::default());
    }

    fn take_current(&self) -> BenchNetworkTimings {
        self.lock()
            .remove(&std::thread::current().id())
            .unwrap_or_default()
    }

    fn with_current<R>(&self, f: impl FnOnce(&mut BenchNetworkTimings) -> R) -> R {
        let thread_id = std::thread::current().id();
        let mut guard = self.lock();
        let current = guard.entry(thread_id).or_default();
        f(current)
    }
}

fn with_current(f: impl FnOnce(&mut BenchNetworkTimings)) {
    BenchCollector::global().with_current(f);
}

fn elapsed_ns(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
}

pub(crate) fn signature_before() -> u64 {
    BenchCollector::global().with_current(|timings| timings.signature_ns)
}

pub(crate) fn record_signature(started: Instant) {
    let elapsed = elapsed_ns(started);
    with_current(|timings| {
        timings.signature_ns = timings.signature_ns.saturating_add(elapsed);
    });
}

pub(crate) fn record_verify(started: Instant) {
    let elapsed = elapsed_ns(started);
    with_current(|timings| {
        timings.verify_ns = timings.verify_ns.saturating_add(elapsed);
    });
}

pub(crate) fn record_open_core(started: Instant) {
    let elapsed = elapsed_ns(started);
    with_current(|timings| {
        timings.open_core_ns = timings.open_core_ns.saturating_add(elapsed);
    });
}

pub(crate) fn record_seal_core(started: Instant, signature_before: u64) {
    with_current(|timings| timings.record_seal_core(started, signature_before));
}

pub fn reset() {
    BenchCollector::global().reset_current();
}

pub fn take() -> BenchNetworkTimings {
    BenchCollector::global().take_current()
}
