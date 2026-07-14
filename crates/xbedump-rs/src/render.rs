use std::fmt::Write;

use crate::crypto;
use crate::kernel_exports::kernel_export_name;
use crate::model::{DumpOptions, KeyKind, Result, Section, Xbe, hex, range};

const INIT_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "XBE_INIT_MOUNT_UTILITY"),
    (0x0000_0002, "XBE_INIT_FORMAT_UTILITY"),
    (0x0000_0004, "XBE_INIT_64M_RAM_ONLY"),
    (0x0000_0008, "XBE_INIT_DONT_SETUP_HDD"),
];
const MEDIA_TYPES: &[(u32, &str)] = &[
    (0x0000_0001, "XBE_MEDIA_HDD"),
    (0x0000_0002, "XBE_MEDIA_XBOX_DVD"),
    (0x0000_0004, "XBE_MEDIA_ANY_CD_OR_DVD"),
    (0x0000_0008, "XBE_MEDIA_CD"),
    (0x0000_0010, "XBE_MEDIA_1LAYER_DVDROM"),
    (0x0000_0020, "XBE_MEDIA_2LAYER_DVDROM"),
    (0x0000_0040, "XBE_MEDIA_1LAYER_DVDR"),
    (0x0000_0080, "XBE_MEDIA_2LAYER_DVDR"),
    (0x0000_0100, "XBE_MEDIA_USB"),
    (0x4000_0000, "XBE_MEDIA_ALLOW_UNLOCKED_HDD"),
];
const GAME_REGIONS: &[(u32, &str)] = &[
    (0x0000_0001, "XBE_REGION_US_CANADA"),
    (0x0000_0002, "XBE_REGION_JAPAN"),
    (0x0000_0004, "XBE_REGION_ELSEWHERE"),
    (0x8000_0000, "XBE_REGION_DEBUG"),
];
const SECTION_FLAGS: &[(u32, &str)] = &[
    (0x0000_0001, "XBE_SEC_WRITABLE"),
    (0x0000_0002, "XBE_SEC_PRELOAD"),
    (0x0000_0004, "XBE_SEC_EXECUTABLE"),
    (0x0000_0008, "XBE_SEC_INSERTED_FILE"),
    (0x0000_0010, "XBE_SEC_RO_HEAD_PAGE"),
    (0x0000_0020, "XBE_SEC_RO_TAIL_PAGE"),
];

pub(crate) fn dump(xbe: &Xbe, options: &DumpOptions) -> Result<String> {
    if options.xbgs {
        return Ok(xbgs(xbe));
    }
    let mut output = String::new();
    if options.header {
        dump_header(&mut output, xbe, options.key)?;
    }
    if options.certificate {
        dump_certificate(&mut output, xbe);
    }
    if options.sections {
        dump_sections(&mut output, xbe)?;
    }
    if options.libraries {
        dump_libraries(&mut output, xbe);
    }
    Ok(output)
}

fn xbgs(xbe: &Xbe) -> String {
    let cert = xbe.certificate();
    let mut output = String::new();
    let _ = writeln!(output, "#\n# {}\n#", cert.title_name);
    let _ = writeln!(output, "[Game-{:08X}]\n", cert.title_id);
    let _ = writeln!(output, "\tNAME={}\n", cert.title_name);
    let _ = writeln!(output, "\tID={:08X}\n", cert.title_id);
    let _ = writeln!(output, "\tHASH_METHOD=HM_UNKNOWN\n");
    let _ = writeln!(output, "\tWHICH_KEY=KEY_SIG\n");
    let _ = writeln!(output, "\tKEY_SIG={}", hex(&cert.signature_key));
    let _ = writeln!(output, "\tKEY_LAN={}", hex(&cert.lan_key));
    for (index, key) in cert.alternate_signature_keys.iter().enumerate() {
        let _ = writeln!(output, "\tKEY_ALT{}={}", index + 1, hex(key));
    }
    output.push('\n');
    output
}

fn dump_header(output: &mut String, xbe: &Xbe, key: KeyKind) -> Result<()> {
    let h = xbe.header();
    let signature_valid = crypto::verify_signature(xbe.data(), h, key)?;
    writeln!(output, "\nXBE header\n~~~~~~~~~~").unwrap();
    writeln!(
        output,
        "Magic                               : {}",
        String::from_utf8_lossy(&h.magic)
    )
    .unwrap();
    write!(
        output,
        "RSA digital signature               : ({})",
        if signature_valid { "Valid" } else { "Fail" }
    )
    .unwrap();
    hex_block(output, &h.signature);
    field(output, "Base address", h.base_address);
    field(output, "Size of all headers:", h.header_size);
    field(output, "Size of entire image", h.image_size);
    field(output, "Size of this header", h.xbe_header_size);
    writeln!(
        output,
        "Image timestamp                     : 0x{:08X} {}",
        h.timestamp,
        timestamp(h.timestamp)
    )
    .unwrap();
    field(output, "Pointer to certificate data", h.certificate_address);
    field(output, "Number of sections", h.section_count);
    field(output, "Pointer to section headers", h.sections_address);
    named_flags(output, "Initialization flags", h.init_flags, INIT_FLAGS);
    writeln!(
        output,
        "Entrypoint                          : 0x{:08X}",
        h.entry_point
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Actual)",
        xbe.decoded_entry_point(key)
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Retail)",
        h.entry_point ^ 0xa8fc_57ab
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Debug)",
        h.entry_point ^ 0x9485_9d4b
    )
    .unwrap();
    field(output, "Pointer to TLS directory", h.tls_directory);
    field(output, "Stack commit size", h.stack_commit);
    field(output, "Heap reserve size", h.heap_reserve);
    field(output, "Heap commit size", h.heap_commit);
    field(output, "PE base address", h.pe_base_address);
    field(output, "PE image size", h.pe_image_size);
    field(output, "PE checksum", h.pe_checksum);
    writeln!(
        output,
        "PE timestamp                        : 0x{:08X} {}",
        h.pe_timestamp,
        timestamp(h.pe_timestamp)
    )
    .unwrap();
    pointer_string(output, xbe, "PC path and filename to EXE", h.pc_exe_path);
    pointer_string(output, xbe, "PC filename to EXE", h.pc_exe_filename);
    pointer_unicode(
        output,
        xbe,
        "PC filename to EXE (Unicode)",
        h.pc_exe_filename_unicode,
    );
    writeln!(
        output,
        "Pointer to kernel thunk table       : 0x{:08X}",
        h.kernel_thunk_table
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Actual)",
        xbe.decoded_kernel_thunk_table(key)
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Retail)",
        h.kernel_thunk_table ^ 0x5b6d_40b6
    )
    .unwrap();
    writeln!(
        output,
        "                                    : 0x{:08X}  (Debug)",
        h.kernel_thunk_table ^ 0xefb1_f152
    )
    .unwrap();
    dump_imports(output, xbe, key)?;
    field(
        output,
        "Non-kernel import table (debug only)",
        h.debug_import_table,
    );
    field(output, "Number of library headers", h.library_count);
    field(output, "Pointer to library headers", h.libraries_address);
    field(output, "Pointer to kernel library header", h.kernel_library);
    field(output, "Pointer to XAPI library header", h.xapi_library);
    field(output, "Pointer to logo bitmap", h.logo_bitmap);
    field(output, "Size of logo bitmap", h.logo_bitmap_size);
    Ok(())
}

fn dump_certificate(output: &mut String, xbe: &Xbe) {
    let cert = xbe.certificate();
    writeln!(output, "\nCertificate\n~~~~~~~~~~~").unwrap();
    field(output, "Size of certificate", cert.size);
    writeln!(
        output,
        "Certificate timestamp               : 0x{:08X} {}",
        cert.timestamp,
        timestamp(cert.timestamp)
    )
    .unwrap();
    field(output, "Title ID", cert.title_id);
    writeln!(
        output,
        "Title name                          : \"{}\"",
        cert.title_name
    )
    .unwrap();
    write!(output, "Alternate title ID's                : ").unwrap();
    let ids: Vec<_> = cert
        .alternate_title_ids
        .iter()
        .copied()
        .take_while(|id| *id != 0)
        .collect();
    if ids.is_empty() {
        writeln!(output, "\n\tnone").unwrap();
    } else {
        for (index, id) in ids.iter().enumerate() {
            if index % 8 == 0 {
                write!(output, "\n\t").unwrap();
            }
            write!(output, "0x{id:x} ").unwrap();
        }
        output.push('\n');
    }
    named_flags(output, "Allowed media types", cert.media_types, MEDIA_TYPES);
    named_flags(
        output,
        "Allowed game regions",
        cert.game_region,
        GAME_REGIONS,
    );
    field(output, "Allowed game rating", cert.game_rating);
    field(output, "Disk number", cert.disk_number);
    field(output, "Version", cert.version);
    writeln!(
        output,
        "LAN key                             : {}",
        spaced_hex(&cert.lan_key)
    )
    .unwrap();
    writeln!(
        output,
        "Signature key                       : {}",
        spaced_hex(&cert.signature_key)
    )
    .unwrap();
    write!(output, "Alternate signature keys            : ").unwrap();
    let flattened: Vec<u8> = cert
        .alternate_signature_keys
        .iter()
        .flatten()
        .copied()
        .collect();
    hex_block(output, &flattened);
}

fn dump_sections(output: &mut String, xbe: &Xbe) -> Result<()> {
    for (index, section) in xbe.sections().iter().enumerate() {
        writeln!(output, "\nSection Header {index}\n~~~~~~~~~~~~~~~~~").unwrap();
        named_flags(output, "Flags", section.flags, SECTION_FLAGS);
        field(output, "Flags", section.flags);
        field(output, "Virtual address", section.virtual_address);
        field(output, "Virtual size", section.virtual_size);
        field(output, "File address", section.file_address);
        field(output, "File size", section.file_size);
        writeln!(
            output,
            "Section name Address                : 0x{:08X} (\"{}\")",
            section.name_address, section.name
        )
        .unwrap();
        writeln!(
            output,
            "Section reference count             : 0x{:08X}",
            section.reference_count as u32
        )
        .unwrap();
        field(
            output,
            "Head shared page reference count",
            section.head_reference_count,
        );
        field(
            output,
            "Tail shared page reference count",
            section.tail_reference_count,
        );
        let digest = xbe.section_digest(section)?;
        write!(
            output,
            "SHA1 hash                           : {}",
            hex(&section.sha1)
        )
        .unwrap();
        if digest == section.sha1 {
            writeln!(output, "  (Valid)").unwrap();
        } else {
            writeln!(output, "   (False)").unwrap();
            writeln!(
                output,
                "SHA1 hash (Needed)                  : {}",
                hex(&digest)
            )
            .unwrap();
        }
    }
    Ok(())
}

fn dump_libraries(output: &mut String, xbe: &Xbe) {
    for (index, library) in xbe.libraries().iter().enumerate() {
        writeln!(output, "\nLibrary {index}\n~~~~~~~~~~").unwrap();
        writeln!(
            output,
            "Library name                        : \"{}\"",
            library.name
        )
        .unwrap();
        writeln!(
            output,
            "Major Version                       : 0x{:08X}",
            library.major_version
        )
        .unwrap();
        writeln!(
            output,
            "Middle Version                      : 0x{:08X}",
            library.middle_version
        )
        .unwrap();
        writeln!(
            output,
            "Minor Version                       : 0x{:08X}",
            library.minor_version
        )
        .unwrap();
        writeln!(
            output,
            "Flags                               : 0x{:08X}",
            library.flags
        )
        .unwrap();
    }
}

fn dump_imports(output: &mut String, xbe: &Xbe, key: KeyKind) -> Result<()> {
    let mut address = xbe.decoded_kernel_thunk_table(key);
    if address == 0 {
        return Ok(());
    }
    let maximum = xbe.data().len() / 4 + 1;
    for _ in 0..maximum {
        let Some(section) = find_virtual_section(xbe.sections(), address) else {
            writeln!(
                output,
                "Couldn't find 0x{address:X}\nKernel thunk table broken!"
            )
            .unwrap();
            return Ok(());
        };
        let within = address.saturating_sub(section.virtual_address);
        let file_address =
            section
                .file_address
                .checked_add(within)
                .ok_or(crate::Error::InvalidValue {
                    context: "kernel thunk file address",
                    value: address.into(),
                })?;
        let offset = usize::try_from(file_address).map_err(|_| crate::Error::InvalidValue {
            context: "kernel thunk file address",
            value: file_address.into(),
        })?;
        let entry = u32::from_le_bytes(
            range(xbe.data(), offset, 4, "kernel thunk entry")?
                .try_into()
                .expect("fixed range"),
        );
        if entry == 0 {
            return Ok(());
        }
        let ordinal = entry & 0x7fff_ffff;
        if let Some(name) = kernel_export_name(ordinal as usize) {
            writeln!(
                output,
                "Kernel import                       : 0x{entry:08X} (@{ordinal}, {name})"
            )
            .unwrap();
        } else {
            writeln!(
                output,
                "Kernel import                       : 0x{entry:08X} (@{ordinal})"
            )
            .unwrap();
        }
        address = address.checked_add(4).ok_or(crate::Error::InvalidValue {
            context: "kernel thunk address",
            value: address.into(),
        })?;
    }
    Err(crate::Error::InvalidValue {
        context: "unterminated kernel thunk table",
        value: address.into(),
    })
}

fn find_virtual_section(sections: &[Section], address: u32) -> Option<&Section> {
    sections.iter().find(|section| {
        address >= section.virtual_address
            && address < section.virtual_address.saturating_add(section.virtual_size)
    })
}

fn pointer_string(output: &mut String, xbe: &Xbe, label: &str, address: u32) {
    let value = read_c_string(xbe, address).unwrap_or_default();
    writeln!(output, "{label:<36}: 0x{address:08X} (\"{value}\")").unwrap();
}

fn pointer_unicode(output: &mut String, xbe: &Xbe, label: &str, address: u32) {
    let value = read_utf16_string(xbe, address).unwrap_or_default();
    writeln!(output, "{label:<36}: 0x{address:08X} (\"{value}\")").unwrap();
}

fn read_c_string(xbe: &Xbe, address: u32) -> Option<String> {
    if address == 0 {
        return None;
    }
    let offset = xbe.virtual_offset(address, "string address").ok()?;
    let tail = xbe.data().get(offset..)?;
    let length = tail.iter().position(|byte| *byte == 0)?;
    Some(String::from_utf8_lossy(&tail[..length]).into_owned())
}

fn read_utf16_string(xbe: &Xbe, address: u32) -> Option<String> {
    if address == 0 {
        return None;
    }
    let offset = xbe.virtual_offset(address, "UTF-16 string address").ok()?;
    let tail = xbe.data().get(offset..)?;
    let mut units = Vec::new();
    for bytes in tail.chunks_exact(2) {
        let unit = u16::from_le_bytes(bytes.try_into().expect("two-byte chunk"));
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    Some(String::from_utf16_lossy(&units))
}

fn field(output: &mut String, label: &str, value: u32) {
    writeln!(output, "{label:<36}: 0x{value:08X}").unwrap();
}

fn named_flags(output: &mut String, label: &str, value: u32, names: &[(u32, &str)]) {
    write!(output, "{label:<36}: ").unwrap();
    if value == 0 {
        writeln!(output, "\n                                    : none").unwrap();
        return;
    }
    writeln!(output, "0x{value:08X}").unwrap();
    for (flag, name) in names {
        if value & flag != 0 {
            writeln!(output, "                                    : {name} ").unwrap();
        }
    }
}

fn hex_block(output: &mut String, bytes: &[u8]) {
    for (index, byte) in bytes.iter().enumerate() {
        if index % 16 == 0 {
            write!(output, "\n                                      ").unwrap();
        }
        write!(output, "{byte:02x} ").unwrap();
    }
    output.push('\n');
}

fn spaced_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

// Deterministic UTC rendering avoids libc/timezone dependencies in the library.
fn timestamp(seconds: u32) -> String {
    let days = i64::from(seconds / 86_400);
    let day_seconds = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = day_seconds / 3600;
    let minute = day_seconds % 3600 / 60;
    let second = day_seconds % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

fn civil_from_days(days_since_epoch: i64) -> (i64, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    (year, month as u32, day as u32)
}
