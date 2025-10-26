use std::{error::Error, fs::File, io::Write};

use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

pub fn convert_i386_to_amd64(code: &[u8], ip: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut r = Vec::new();

    let decoder = Decoder::with_ip(32, code, ip, DecoderOptions::NONE);
    let mut formatter = NasmFormatter::new();

    let mut sb = String::new();

    for instr in decoder {
        let mut output = String::new();
        formatter.format(&instr, &mut output);
        println!("{:08X} {}", instr.ip(), output);

        sb += &format!("{:08X} {}", instr.ip(), output);
        sb += "\r\n";
    }

    File::create("./code.txt")
        .unwrap()
        .write_all(sb.as_bytes())
        .unwrap();

    Ok(r)
}
