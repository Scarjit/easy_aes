use std::error::Error;

pub mod aes256_gcm_siv;
pub mod x_chacha20_poly1305;

pub trait EasyCryptoAead {
    fn encrypt(plaintext: &str, key: &str) -> Result<String, Box<dyn Error>>;
    fn decrypt(ciphertext: &str, key: &str) -> Result<String, Box<dyn Error>>;
}
