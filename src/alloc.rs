use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

pub const NAMED_PHASES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    StartupDns,
    Serving,
    BackgroundRefresh,
    Logging,
    Shutdown,
}

impl Phase {
    pub const ALL: [Phase; NAMED_PHASES] = [
        Phase::StartupDns,
        Phase::Serving,
        Phase::BackgroundRefresh,
        Phase::Logging,
        Phase::Shutdown,
    ];

    const fn index(self) -> usize {
        match self {
            Phase::StartupDns => 0,
            Phase::Serving => 1,
            Phase::BackgroundRefresh => 2,
            Phase::Logging => 3,
            Phase::Shutdown => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Alloc,
    Dealloc,
    Realloc,
}

impl Event {
    const fn index(self) -> usize {
        match self {
            Event::Alloc => 0,
            Event::Dealloc => 1,
            Event::Realloc => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub allocs: u64,
    pub deallocs: u64,
    pub reallocs: u64,
}

impl Counts {
    #[must_use]
    pub const fn all_zero(self) -> bool {
        self.allocs == 0 && self.deallocs == 0 && self.reallocs == 0
    }
}

type PhaseCounts = [[u64; 3]; NAMED_PHASES];

thread_local! {
    static CURRENT_PHASE: Cell<Option<Phase>> = const { Cell::new(None) };
    static MEASURED: Cell<PhaseCounts> = const { Cell::new([[0; 3]; NAMED_PHASES]) };
}

fn measure(event: Event) {
    let phase = CURRENT_PHASE.try_with(Cell::get).unwrap_or(None);
    let Some(phase) = phase else {
        return;
    };
    let p = phase.index();
    let e = event.index();
    let _ = MEASURED.try_with(|cell| {
        let mut counts = cell.get();
        counts[p][e] = counts[p][e].saturating_add(1);
        cell.set(counts);
    });
}

struct PhaseGuard {
    prev: Option<Phase>,
}

impl Drop for PhaseGuard {
    fn drop(&mut self) {
        let _ = CURRENT_PHASE.try_with(|cell| cell.set(self.prev));
    }
}

pub fn run_phase<R>(phase: Phase, f: impl FnOnce() -> R) -> (R, Counts) {
    let before = MEASURED.with(Cell::get);
    let _guard = PhaseGuard {
        prev: CURRENT_PHASE.with(|cell| cell.replace(Some(phase))),
    };
    let value = f();
    let after = MEASURED.with(Cell::get);
    let p = phase.index();
    let counts = Counts {
        allocs: after[p][0] - before[p][0],
        deallocs: after[p][1] - before[p][1],
        reallocs: after[p][2] - before[p][2],
    };
    (value, counts)
}

#[must_use]
pub fn active_phase() -> Option<Phase> {
    CURRENT_PHASE.with(Cell::get)
}

pub struct Counting;

// SAFETY: `Counting` is a zero-sized marker allocator — it holds no pointers,
// no layout state, and no interior mutable state of its own. Every operation
// forwards to the process `System` global allocator (which upholds the
// `GlobalAlloc` contract), so the trait obligations — `alloc` returns a slot
// aligned and sized for `layout` or dangling/zero, and `dealloc`/`realloc`
// receive exactly a pointer previously returned by this allocator with its
// matching layout — are discharged by `System`, never by this type. Under
// `alloc-witness` this is installed as a `#[global_allocator]`; being
// zero-sized it is automatically `Sync`, so there is no shared mutable state
// to race.
unsafe impl GlobalAlloc for Counting {
    // SAFETY: `layout` is forwarded unchanged to `System::alloc`, which is
    // sound for any caller-supplied `Layout` under the `GlobalAlloc` contract;
    // the returned pointer (or dangling/zero on OOM) is exactly what `System`
    // guarantees, and `measure` touches only thread-local counters, never the
    // returned pointer.
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        measure(Event::Alloc);
        // SAFETY: `System::alloc` requires only a `Layout`; forwarding the
        // caller's `layout` as-is introduces no assumption beyond the trait
        // contract, so this call is sound.
        unsafe { System.alloc(layout) }
    }

    // SAFETY: the caller (global-allocator machinery, or test code honouring
    // the trait contract) passes a `ptr` previously returned by this
    // allocator's `alloc`/`realloc` with the same `layout`. Because every
    // pointer this allocator hands out came from `System`, forwarding the
    // `(ptr, layout)` pair back to `System::dealloc` is sound; `measure`
    // touches only thread-local counters, never `ptr`.
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        measure(Event::Dealloc);
        // SAFETY: `System::dealloc` requires a `(ptr, layout)` pair satisfying
        // the `GlobalAlloc` contract; the caller supplies exactly that (a
        // pointer from a prior `System`-backed alloc with its original
        // layout), so the transitive precondition holds.
        unsafe { System.dealloc(ptr, layout) }
    }

    // SAFETY: `ptr`/`layout` are the `GlobalAlloc::realloc` inputs — a
    // previously returned pointer with its original layout, or dangling (in
    // which case `realloc` behaves as `alloc`) — and `new_size` is an arbitrary
    // caller-chosen size; forwarding them to `System::realloc` discharges the
    // contract, and `measure` touches only thread-local counters, never `ptr`.
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        measure(Event::Realloc);
        // SAFETY: `System::realloc` implements the `GlobalAlloc` realloc
        // contract (shrink, grow, or move the block as needed) for the
        // `(ptr, layout, new_size)` triple supplied by the caller, so this
        // forwarding call is sound under those same preconditions.
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[cfg(feature = "alloc-witness")]
#[global_allocator]
static WITNESS: Counting = Counting;
