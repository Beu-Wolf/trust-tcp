use std::io;
use std::thread;
use std::io::prelude::*;


fn main() -> io::Result<()>{
    let mut i = trust::Interface::new()?;
    let mut l1 = i.bind(7000)?;
    //let mut l2 = i.bind(7001)?;
    let jh1 = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("Got connection!");
            let n = stream.read(&mut [0]).unwrap();
            eprintln!("read data"); 
            assert_eq!(n, 0);
            eprintln!("no more data!")
        }
    });

    // let jh2 = thread::spawn(move || {
    //     while let Ok(_stream) = l2.accept() {
    //         eprint!("Got connection!");
    //     }
    // });
    jh1.join().unwrap();
    //jh2.join().unwrap();
    Ok(())
}
