use std::convert::From;
use crate::mmap::Mmap;
pub use crate::core::{
   Elf64_Ehdr,
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
    pub fn as_ref(mem: &Mmap) -> Result<&Self, ()> {
        let elfhdr = unsafe { &*mem.mem().cast::<Elf64_Ehdr>() };

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
