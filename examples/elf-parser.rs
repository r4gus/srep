//! This example is inspired by "Coding an ELF Parser", Learning Linux 
//! Binary Analysis, by Ryan O'Neill.

use srep::mmap::*;
use srep::mapping;
use srep::elf::*;
use std::fs::File;

fn main() -> std::io::Result<()> {
    // Open the hello world program.
    let file = File::open("assets/hello")?;
    // Get the length of the file.
    let len = file.metadata()?.len();
    
    // Create a new file backed memmory mapping.
    let mem = Mmap::new(len, Prot::Read, mapping!(MType::Private), Some(&file), 0)
        .expect("mapping should be successful");
    // ---> The file can be closed now.
    
    let ehdr = Elf64_Ehdr::from_ptr(&mem).expect("elf header should be present");
    let phdr = Elf64_Phdr::from_ptr(&mem, &ehdr).expect("program header present");
    let shdr = Elf64_Shdr::from_ptr(&mem, &ehdr).expect("section header present");

    println!("Type: {}", ehdr.typ());
    println!("Program Entry point: 0x{:x}", ehdr.e_entry);

    Ok(())
}
