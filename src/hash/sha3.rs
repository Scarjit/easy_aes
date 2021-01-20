use crate::hash::EasyCryptoHash;
use sha3::{Digest, Sha3_512};
use std::error::Error;

pub struct EasySHA3_512 {}
impl EasyCryptoHash for EasySHA3_512 {
    fn hash(input: &str) -> Result<String, Box<dyn Error>> {
        let mut hasher = Sha3_512::new();
        hasher.update(input);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}
