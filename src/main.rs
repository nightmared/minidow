#![feature(asm)]

use rand::seq::SliceRandom;

const MULTIPLE_OFFSET: usize = 4096;
const NB_TRIES: usize = 17;

static TO_LEAK: usize = 0x0123456789abcdef;
static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + 64] = [127; 256 * MULTIPLE_OFFSET + 64];
static mut HISTOGRAM: [[u64; NB_TRIES]; 256] = [[0; NB_TRIES]; 256];

unsafe fn measure_addr(target_adress: *const u8) -> u8 {
    let mut base_addr = TEST_ARR.as_ptr() as usize;
    // align on a cache line size
    base_addr = (base_addr + 64) & 0xffffffffffffffc0;
    let mut rng = rand::thread_rng();
    let mut v = (0..256).collect::<Vec<usize>>();

    for j in 0..NB_TRIES {
        v.shuffle(&mut rng);

        // prefetch an entry for ensuring TLB won't impact the measures
        std::ptr::read_volatile(base_addr as *const u8);

        // flush
        for i in 0..((256 * MULTIPLE_OFFSET) / 64) {
            core::arch::x86_64::_mm_clflush((base_addr as usize + i * 64) as *const u8 as *mut u8);
        }

        // perform the access
        asm!("movzx rax, byte ptr [{0}]", "imul rax, {2}", "add {1}, rax", "movzx rax, byte ptr [{1}]", in(reg) target_adress, inout(reg) base_addr => _, in(reg) MULTIPLE_OFFSET, out("rax") _);

        for i in 0..256 {
            let count_addr = base_addr as usize + i * MULTIPLE_OFFSET;
            let delta_tsc;
            // measure the time
            let mut res: usize;
            asm!("mfence", "lfence", "rdtsc", "lfence", "shl rdx, $32", "or rax, rdx", "mov rcx, rax",
                 "movzx r9, byte ptr [{0}]",
                 "mfence", "lfence", "rdtsc", "shl rdx, $32", "or rax, rdx", "sub rax, rcx",
                 in(reg) count_addr,
                 out("rdx") _, out("rcx") _, out("rax") delta_tsc, out("r9") res);
            println!("{}", std::ptr::read_volatile(count_addr as *const u8));
            println!("{}", res);
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
    println!("{:?}", medians);
    println!("{}", medians[239]);

    0
}

fn main() {
    println!("{}", unsafe {
        measure_addr(&TO_LEAK as *const usize as *const u8)
    });
}
