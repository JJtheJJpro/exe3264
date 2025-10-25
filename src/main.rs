use object::{
    LittleEndian,
    pe::{
        IMAGE_SCN_ALIGN_1BYTES, IMAGE_SCN_ALIGN_2BYTES, IMAGE_SCN_ALIGN_4BYTES,
        IMAGE_SCN_ALIGN_8BYTES, IMAGE_SCN_ALIGN_16BYTES, IMAGE_SCN_ALIGN_32BYTES,
        IMAGE_SCN_ALIGN_64BYTES, IMAGE_SCN_ALIGN_128BYTES, IMAGE_SCN_ALIGN_256BYTES,
        IMAGE_SCN_ALIGN_512BYTES, IMAGE_SCN_ALIGN_1024BYTES, IMAGE_SCN_ALIGN_2048BYTES,
        IMAGE_SCN_ALIGN_4096BYTES, IMAGE_SCN_ALIGN_8192BYTES, IMAGE_SCN_CNT_CODE,
        IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_CNT_UNINITIALIZED_DATA, IMAGE_SCN_GPREL,
        IMAGE_SCN_LNK_COMDAT, IMAGE_SCN_LNK_INFO, IMAGE_SCN_LNK_NRELOC_OVFL, IMAGE_SCN_LNK_REMOVE,
        IMAGE_SCN_MEM_DISCARDABLE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_NOT_CACHED,
        IMAGE_SCN_MEM_NOT_PAGED, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_SHARED, IMAGE_SCN_MEM_WRITE,
        ImageDosHeader, ImageNtHeaders32,
    },
    read::pe::ImageNtHeaders,
};
use std::{
    fs::File,
    io::{Write, stdout},
};

trait VecManipulate {
    fn copy_from_slice_at(&mut self, src: &[u8], index: usize);
    fn push_u16_le(&mut self, v: u16);
    fn push_u32_le(&mut self, v: u32);
    fn push_u64_le(&mut self, v: u64);
    fn push_arr<const N: usize>(&mut self, arr: [u8; N]);
}
impl VecManipulate for Vec<u8> {
    fn copy_from_slice_at(&mut self, src: &[u8], index: usize) {
        if index + src.len() > self.len() {
            self.resize(index + src.len(), 0);
        }
        for i in 0..src.len() {
            self[index + i] = src[i];
        }
    }

    fn push_u16_le(&mut self, v: u16) {
        self.push((v & 0xFF) as u8);
        self.push((v >> 8) as u8);
    }
    fn push_u32_le(&mut self, v: u32) {
        self.push((v & 0xFF) as u8);
        self.push(((v >> (8 * 1)) & 0xFF) as u8);
        self.push(((v >> (8 * 2)) & 0xFF) as u8);
        self.push(((v >> (8 * 3)) & 0xFF) as u8);
    }
    fn push_u64_le(&mut self, v: u64) {
        self.push((v & 0xFF) as u8);
        self.push(((v >> (8 * 1)) & 0xFF) as u8);
        self.push(((v >> (8 * 2)) & 0xFF) as u8);
        self.push(((v >> (8 * 3)) & 0xFF) as u8);
        self.push(((v >> (8 * 4)) & 0xFF) as u8);
        self.push(((v >> (8 * 5)) & 0xFF) as u8);
        self.push(((v >> (8 * 6)) & 0xFF) as u8);
        self.push(((v >> (8 * 7)) & 0xFF) as u8);
    }

    fn push_arr<const N: usize>(&mut self, arr: [u8; N]) {
        for u in arr {
            self.push(u);
        }
    }
}

fn main() {
    const PROG1: &'static [u8] = include_bytes!("../progtest1.exe");
    const PROG1FIX: &'static str = "./progtest1-64.exe";
    let output = &mut Vec::new();

    println!("File Info:");
    println!("  Name: {}", "progtest1.exe");
    println!("  Size: {} bytes", PROG1.len());
    println!();

    print!("Commencing Valid Checks...");
    stdout().flush().unwrap();

    if PROG1[..2] != *b"MZ" {
        eprintln!(
            "Valid Check 1 failed: DOS header magic incorrect; found '{}', expected 'MZ'.",
            String::from_utf8_lossy(&PROG1[..2])
        );
        return;
    }

    let mz = match ImageDosHeader::parse(&PROG1[..64]) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Valid Check 2 failed: MZ header parser error occured. See below for more.");
            eprintln!("{e}");
            return;
        }
    };

    let pe_start = mz.e_lfanew.get(LittleEndian) as usize;
    output.copy_from_slice_at(&PROG1[..pe_start], 0);

    if PROG1[pe_start..pe_start + 4] != *b"PE\0\0" {
        eprintln!(
            "Valid Check 3 failed: PE header magic incorrect; found '{}', expected 'PE\0\0'.",
            String::from_utf8_lossy(&PROG1[pe_start..pe_start + 4])
        );
        return;
    }
    output.copy_from_slice_at(&PROG1[pe_start..pe_start + 4], pe_start);

    let mut section_start_old = 0;
    let (pe, dirs) = match ImageNtHeaders32::parse(&PROG1[pe_start..], &mut section_start_old) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Valid Check 4 failed: PE COFF Image File header parser error occured. See below for more."
            );
            eprintln!("{e}");
            return;
        }
    };
    if pe.file_header.machine.get(LittleEndian) != 0x014C {
        eprintln!("Valid Check 5 failed: Program only supports I386 architecture.");
        eprintln!(
            "                      Found 0x{:04X}, expected 0x014C.",
            pe.file_header.machine.get(LittleEndian)
        );
        eprintln!();
        eprintln!("https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#machine-types");
        return;
    }

    output.push_u16_le(0x8664); // From I386 to AMD64
    output.push_u16_le(pe.file_header.number_of_sections.get(LittleEndian));
    output.push_u32_le(pe.file_header.time_date_stamp.get(LittleEndian));
    output.push_u32_le(pe.file_header.pointer_to_symbol_table.get(LittleEndian));
    output.push_u32_le(pe.file_header.number_of_symbols.get(LittleEndian));
    output.push_u16_le(0x00F0); // from 0xE0 (224) to 0xF0 (240)
    output.push_u16_le((pe.file_header.characteristics.get(LittleEndian) & !0x0100) | 0x0020); // Not 32-bit-word arch AND can handle > 2-GB addresses

    let pe_opt = pe.optional_header;

    if pe_opt.magic.get(LittleEndian) != 0x010B {
        eprintln!(
            "Valid Check 6 failed: Mismatched magic for optional header; found 0x{:04X}, expected 0x010B.",
            pe_opt.magic.get(LittleEndian)
        );
        if pe_opt.magic.get(LittleEndian) == 0x0107 {
            eprintln!("Seems like this EXE is a ROM image.  No can do.");
        }
        return;
    }

    println!("Valid Checks complete!");
    print!("Rewriting Header Info...");
    stdout().flush().unwrap();

    output.push_u16_le(0x020B);
    output.push(pe_opt.major_linker_version);
    output.push(pe_opt.minor_linker_version);
    output.push_u32_le(pe_opt.size_of_code.get(LittleEndian));
    output.push_u32_le(pe_opt.size_of_initialized_data.get(LittleEndian));
    output.push_u32_le(pe_opt.size_of_uninitialized_data.get(LittleEndian));
    output.push_u32_le(pe_opt.address_of_entry_point.get(LittleEndian));
    output.push_u32_le(pe_opt.base_of_code.get(LittleEndian));
    // BaseOfData is present in 32-bit, absent in 64-bit.  Skip field.
    // However, this does realign with the ImageBase field (4 bytes in 32-bit, 8 bytes in 64-bit).

    output.push_u64_le(pe_opt.image_base.get(LittleEndian) as u64);
    output.push_u32_le(pe_opt.section_alignment.get(LittleEndian));
    output.push_u32_le(pe_opt.file_alignment.get(LittleEndian));
    output.push_u16_le(pe_opt.major_operating_system_version.get(LittleEndian));
    output.push_u16_le(pe_opt.minor_operating_system_version.get(LittleEndian));
    output.push_u16_le(pe_opt.major_image_version.get(LittleEndian));
    output.push_u16_le(pe_opt.minor_image_version.get(LittleEndian));
    output.push_u16_le(pe_opt.major_subsystem_version.get(LittleEndian));
    output.push_u16_le(pe_opt.minor_subsystem_version.get(LittleEndian));
    output.push_u32_le(pe_opt.win32_version_value.get(LittleEndian));
    output.push_u32_le(pe_opt.size_of_image.get(LittleEndian));
    output.push_u32_le(pe_opt.size_of_headers.get(LittleEndian));
    output.push_u32_le(pe_opt.check_sum.get(LittleEndian));
    output.push_u16_le(pe_opt.subsystem.get(LittleEndian));
    output.push_u16_le(pe_opt.dll_characteristics.get(LittleEndian) | 0x0020); // If it is DLL, make sure it can handle high entropy 64-bit vaddr space
    output.push_u64_le(pe_opt.size_of_stack_reserve.get(LittleEndian) as u64);
    output.push_u64_le(pe_opt.size_of_stack_commit.get(LittleEndian) as u64);
    output.push_u64_le(pe_opt.size_of_heap_reserve.get(LittleEndian) as u64);
    output.push_u64_le(pe_opt.size_of_heap_commit.get(LittleEndian) as u64);
    output.push_u32_le(pe_opt.loader_flags.get(LittleEndian));
    output.push_u32_le(pe_opt.number_of_rva_and_sizes.get(LittleEndian));

    for dir in dirs.enumerate() {
        output.push_u32_le(dir.1.virtual_address.get(LittleEndian));
        output.push_u32_le(dir.1.size.get(LittleEndian));
    }

    let sections = pe.sections(&PROG1[pe_start..], section_start_old).unwrap();
    for (_, section) in sections.enumerate() {
        output.push_arr(section.name);
        output.push_u32_le(section.virtual_size.get(LittleEndian));
        output.push_u32_le(section.virtual_address.get(LittleEndian));
        output.push_u32_le(section.size_of_raw_data.get(LittleEndian));
        output.push_u32_le(section.pointer_to_raw_data.get(LittleEndian));
        output.push_u32_le(section.pointer_to_relocations.get(LittleEndian));
        output.push_u32_le(section.pointer_to_linenumbers.get(LittleEndian));
        output.push_u16_le(section.number_of_relocations.get(LittleEndian));
        output.push_u16_le(section.number_of_linenumbers.get(LittleEndian));
        output.push_u32_le(section.characteristics.get(LittleEndian)); // Useful mega
    }

    println!("Headers Written!");
    println!("Converting Sections...");

    for (i, section) in sections.enumerate() {
        let (offset, size) = section.pe_file_range();
        let (offset, size) = (offset as usize, size as usize);

        // Here, we need to convert raw byte code from 32-bit to 64-bit.
        let characteristics = section.characteristics.get(LittleEndian);
        //println!("0x{characteristics:08X}");
        print!(
            "Section {i} ({}) Characteristics: ",
            str::from_utf8(section.raw_name()).unwrap()
        );
        let mut edit = false;
        {
            if characteristics & IMAGE_SCN_CNT_CODE != 0 {
                if edit {
                    print!(" | ContainsCode");
                } else {
                    edit = true;
                    print!("ContainsCode");
                }
            }
            if characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA != 0 {
                if edit {
                    print!(" | ContainsInitData");
                } else {
                    edit = true;
                    print!("ContainsInitData");
                }
            }
            if characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA != 0 {
                if edit {
                    print!(" | ContainsUninitData");
                } else {
                    edit = true;
                    print!("ContainsUninitData");
                }
            }
            if characteristics & IMAGE_SCN_LNK_INFO != 0 {
                if edit {
                    print!(" | LinkInfo");
                } else {
                    edit = true;
                    print!("LinkInfo");
                }
            }
            if characteristics & IMAGE_SCN_LNK_REMOVE != 0 {
                if edit {
                    print!(" | LinkRemove");
                } else {
                    edit = true;
                    print!("LinkRemove");
                }
            }
            if characteristics & IMAGE_SCN_LNK_COMDAT != 0 {
                if edit {
                    print!(" | LinkCOMDAT");
                } else {
                    edit = true;
                    print!("LinkCOMDAT");
                }
            }
            if characteristics & IMAGE_SCN_GPREL != 0 {
                if edit {
                    print!(" | GPREL");
                } else {
                    edit = true;
                    print!("GPREL");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_1BYTES != 0 {
                if edit {
                    print!(" | Align1Byte");
                } else {
                    edit = true;
                    print!("Align1Byte");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_2BYTES != 0 {
                if edit {
                    print!(" | Align2Bytes");
                } else {
                    edit = true;
                    print!("Align2Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_4BYTES != 0 {
                if edit {
                    print!(" | Align4Bytes");
                } else {
                    edit = true;
                    print!("Align4Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_8BYTES != 0 {
                if edit {
                    print!(" | Align8Bytes");
                } else {
                    edit = true;
                    print!("Align8Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_16BYTES != 0 {
                if edit {
                    print!(" | Align16Bytes");
                } else {
                    edit = true;
                    print!("Align16Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_32BYTES != 0 {
                if edit {
                    print!(" | Align32Bytes");
                } else {
                    edit = true;
                    print!("Align32Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_64BYTES != 0 {
                if edit {
                    print!(" | Align64Bytes");
                } else {
                    edit = true;
                    print!("Align64Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_128BYTES != 0 {
                if edit {
                    print!(" | Align128Bytes");
                } else {
                    edit = true;
                    print!("Align128Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_256BYTES != 0 {
                if edit {
                    print!(" | Align256Bytes");
                } else {
                    edit = true;
                    print!("Align256Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_512BYTES != 0 {
                if edit {
                    print!(" | Align512Bytes");
                } else {
                    edit = true;
                    print!("Align512Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_1024BYTES != 0 {
                if edit {
                    print!(" | Align1024Bytes");
                } else {
                    edit = true;
                    print!("Align1024Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_2048BYTES != 0 {
                if edit {
                    print!(" | Align2048Bytes");
                } else {
                    edit = true;
                    print!("Align2048Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_4096BYTES != 0 {
                if edit {
                    print!(" | Align4096Bytes");
                } else {
                    edit = true;
                    print!("Align4096Bytes");
                }
            }
            if characteristics & IMAGE_SCN_ALIGN_8192BYTES != 0 {
                if edit {
                    print!(" | Align8192Bytes");
                } else {
                    edit = true;
                    print!("Align8192Bytes");
                }
            }
            if characteristics & IMAGE_SCN_LNK_NRELOC_OVFL != 0 {
                if edit {
                    print!(" | LinkNRelocOVFL");
                } else {
                    edit = true;
                    print!("LinkNRelocOVFL");
                }
            }
            if characteristics & IMAGE_SCN_MEM_DISCARDABLE != 0 {
                if edit {
                    print!(" | MemDiscard");
                } else {
                    edit = true;
                    print!("MemDiscard");
                }
            }
            if characteristics & IMAGE_SCN_MEM_NOT_CACHED != 0 {
                if edit {
                    print!(" | MemNotCached");
                } else {
                    edit = true;
                    print!("MemNotCached");
                }
            }
            if characteristics & IMAGE_SCN_MEM_NOT_PAGED != 0 {
                if edit {
                    print!(" | MemNotPaged");
                } else {
                    edit = true;
                    print!("MemNotPaged");
                }
            }
            if characteristics & IMAGE_SCN_MEM_SHARED != 0 {
                if edit {
                    print!(" | MemShared");
                } else {
                    edit = true;
                    print!("MemShared");
                }
            }
            if characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
                if edit {
                    print!(" | MemExecute");
                } else {
                    edit = true;
                    print!("MemExecute");
                }
            }
            if characteristics & IMAGE_SCN_MEM_READ != 0 {
                if edit {
                    print!(" | MemRead");
                } else {
                    edit = true;
                    print!("MemRead");
                }
            }
            if characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                if edit {
                    print!(" | MemWrite");
                } else {
                    edit = true;
                    print!("MemWrite");
                }
            }
        }
        if !edit {
            if characteristics == 0 {
                print!("Null");
            } else {
                print!("Reserved Flags Only");
            }
        }
        println!();

        match str::from_utf8(section.raw_name()).unwrap() {
            ".text" => {
                println!(".text -> code recompile x86 => x64");

            }
            ".rdata" => {
                println!(".rdata -> widen any pointers");
            }
            ".data" => {
                println!(".rdata -> widen any pointers");
            }
            ".reloc" => {
                println!(".rdata -> rebuild with dir64");
            }
            s => {
                println!("{s} -> copy");
                output.copy_from_slice_at(&PROG1[offset..offset + size], offset);
            }
        }
    }

    let fa = pe_opt.file_alignment.get(LittleEndian) as usize;
    while output.len() % fa != 0 {
        output.push(0);
    }

    let mut outputfile = File::create(PROG1FIX).unwrap();
    outputfile.write(output).unwrap();
}
