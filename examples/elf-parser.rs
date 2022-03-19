use srep::mmap::*;
use srep::mapping;
use std::fs::File;

fn main() -> std::io::Result<()> {
    // Open the hello world program.
    let file = File::open("../assets/hello")?;
    // Get the length of the file.
    let len = file.metadata()?.len();
    
    // Create a new file backed memmory mapping.
    let mem = Mmap::new(len, Prot::Read, mapping!(MType::Private), Some(&file), 0)
        .expect("mapping should be successful");
    // ---> The file can be closed now.

    Ok(())
}
