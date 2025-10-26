pub fn rebuild_reloc(original: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut input = original;

    while input.len() >= 8 {
        let va = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let size = u32::from_le_bytes(input[4..8].try_into().unwrap());
        if size < 8 || size as usize > input.len() {
            break;
        }

        // Copy block header
        out.extend_from_slice(&va.to_le_bytes());
        out.extend_from_slice(&size.to_le_bytes());

        // Convert each entry
        let entries = &input[8..size as usize];
        for chunk in entries.chunks(2) {
            let entry = u16::from_le_bytes(chunk.try_into().unwrap());
            let typ = entry >> 12;
            let offs = entry & 0x0fff;

            let new_typ = match typ {
                0x3 => 0xA, // HIGHLOW → DIR64
                _ => typ,   // keep others (e.g., ABSOLUTE)
            };
            let new_entry = (new_typ << 12) | offs;
            out.extend_from_slice(&(new_entry as u16).to_le_bytes());
        }

        input = &input[size as usize..];
    }

    out
}
