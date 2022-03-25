use std::convert::From;
use std::mem;
use crate::mmap::Mmap;
pub use crate::core::{
   Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr,
   Elf64_Half, Elf64_Word, Elf64_Addr, Elf64_Off,
};
use crate::core::{
    ET_REL, ET_EXEC, ET_DYN, ET_CORE, ET_NONE,
};

/// An ELF file has always one of the following types.
pub enum ElfType {
    /// The type is unknown or not defined.
    None,
    /// This file type marks relocatable (i.e. object files) that
    /// contains position independent code.
    Relocatable,
    /// This file is an executable.
    Executable,
    /// This file either uses shared object files (.so) or is one.
    Dynamic,
    /// Marks a core file. A core file is produced during a program
    /// crash (e.g. SIGSEGV) and contains information about what
    /// went wrong.
    Core,
}

impl std::fmt::Display for ElfType {
    fn fmt(&self, out: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(out, "{}",
            match *self {
                ElfType::None => "NONE (unknown type)", 
                ElfType::Relocatable => "REL (relocatable file)",
                ElfType::Executable => "EXEC (executable file)",
                ElfType::Dynamic => "DYN (shared object file)",
                ElfType::Core => "CORE (core file)",
            }
        )
    }
}

impl Elf64_Ehdr {
    /// Try to get a reference to a [`Elf64_Ehdr`] from the given memory mapping.
    ///
    /// This function returns successful if the first four bytes in
    /// memory hold the value 0x7f e l f (the correct magic number).
    pub fn from_ptr(mem: &Mmap) -> Result<&Self, ()> {
        if mem::size_of::<Elf64_Ehdr>() > mem.len() as usize {
            return Err(())
        }

        let elfhdr = unsafe { &*mem.raw().cast::<Elf64_Ehdr>() };

        // Sanity check: first 4 bytes should be 0x7f-e-l-f.
        if elfhdr.e_ident[..4] != [0x7f, 0x45, 0x4c, 0x46] {
            Err(())
        } else {
            Ok(elfhdr)
        }
    }

    pub fn typ(&self) -> ElfType {
        match self.e_type as u32 {
            ET_REL => ElfType::Relocatable,
            ET_EXEC => ElfType::Executable,
            ET_DYN => ElfType::Dynamic,
            ET_CORE => ElfType::Core,
            _ => ElfType::None,
        }
    }
}

impl Elf64_Phdr {
    pub fn from_ptr<'a, 'b>(mem: &'a Mmap, ehdr: &'b Elf64_Ehdr) -> Result<&'a Self, ()> {
        // Check that we don't access memory that is out of bounds.
        if ehdr.e_phoff as usize + mem::size_of::<Elf64_Phdr>() > mem.len() as usize {
            return Err(())
        }

        unsafe {
           Ok(&*mem.raw().add(ehdr.e_phoff as usize).cast::<Elf64_Phdr>())
        }
    }
}

impl Elf64_Shdr {
    pub fn from_ptr<'a, 'b>(mem: &'a Mmap, ehdr: &'b Elf64_Ehdr) -> Result<&'a Self, ()> {
        // Check that we don't access memory that is out of bounds.
        if ehdr.e_shoff as usize + mem::size_of::<Elf64_Shdr>() > mem.len() as usize {
            return Err(())
        }

        unsafe {
           Ok(&*mem.raw().add(ehdr.e_shoff as usize).cast::<Elf64_Shdr>())
        }
    }
}
