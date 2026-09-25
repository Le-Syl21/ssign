//! Every reader in ssign-core that takes bytes from outside: the PE and MSI
//! files it is asked to sign, a PEM certificate, and the Certum service's
//! multipart and DER answers. The first byte picks the reader, the rest is the
//! input. Any of them may fail; none may panic, hang or overflow the stack.

#![no_main]

use libfuzzer_sys::fuzz_target;
use ssign_core::{asn1, authenticode, client, msi};

/// DER nests, and a malformed length can make a child as big as its parent:
/// the walk stops here so the harness itself stays bounded.
const MAX_DEPTH: usize = 32;

fn walk(tlv: &[u8], depth: usize) {
    if depth > MAX_DEPTH {
        return;
    }
    if let Ok(children) = asn1::children(tlv) {
        for child in children {
            walk(child, depth + 1);
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&pick, body)) = data.split_first() else {
        return;
    };
    match pick % 5 {
        0 => drop(authenticode::pe_hash(body)),
        1 => drop(msi::msi_hash(body)),
        2 => drop(authenticode::pem_to_der(body)),
        3 => {
            drop(client::multipart_part(body, "certificate"));
            drop(client::multipart_part(body, "res"));
        }
        _ => walk(body, 0),
    }
});
