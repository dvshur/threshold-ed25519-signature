use std::convert::{TryFrom, TryInto};

#[derive(Debug, PartialEq, Eq)]
pub struct Secret([u8; 32]);

impl TryFrom<&str> for Secret {
    type Error = ();

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut res = [0u8; 32];

        let bytes = value.as_bytes();

        if bytes.len() > 32 {
            return Err(());
        }

        for (i, b) in bytes.iter().enumerate() {
            res[i] = b.clone();
        }

        Ok(Secret(res))
    }
}

impl TryInto<String> for Secret {
    type Error = ();

    fn try_into(self) -> Result<String, Self::Error> {
        let s2 = self
            .0
            .iter()
            .take_while(|b| **b != 0u8)
            .map(|b| b.clone())
            .collect::<Vec<_>>();

        String::from_utf8(s2).map_err(|_| ())
    }
}
