pub fn to_canonical_bytes(s: &str) -> Result<[u8; 32], ()> {
    let mut res = [0u8; 32];

    let bytes = s.as_bytes();

    if bytes.len() > 32 {
        return Err(());
    }

    for (i, b) in bytes.iter().enumerate() {
        res[i] = b.clone();
    }

    Ok(res)
}

pub fn from_canonical_bytes(bytes: &[u8; 32]) -> Result<String, ()> {
    let s2 = bytes
        .iter()
        .take_while(|b| **b != 0u8)
        .map(|b| b.clone())
        .collect::<Vec<_>>();

    String::from_utf8(s2).map_err(|_| ())
}
