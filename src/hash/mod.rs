use std::error::Error;
pub mod sha3;

pub trait EasyCryptoHash {
    fn hash(input: &str) -> Result<String, Box<dyn Error>>;
}
