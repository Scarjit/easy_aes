use std::error::Error;
pub mod salsa20_kangerootwelve;

pub trait EasyCryptoCustomAEAD {
    fn encrypt(input: &str, key: &str) -> Result<String, Box<dyn Error>>;
    fn decrypt(input: &str, key: &str) -> Result<String, Box<dyn Error>>;
}
