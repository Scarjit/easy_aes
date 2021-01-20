use crate::EasyCryptoAead;
use std::error::Error;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{NewAead, Aead};
use rand::Rng;
use chacha20poly1305::aead::generic_array::GenericArray;

pub struct EasyXChaCha20Poly1305{}
impl EasyCryptoAead for EasyXChaCha20Poly1305{
    ///Encrypt given data string, returns ciphertext & nounce
    ///Prepends ciphertext with nounce
    ///Panics if chacha key is not 32 chars long
    fn encrypt(plaintext: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let mut rng = rand::thread_rng();
        let key = GenericArray::from_slice(key.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let n = (0..(192 / 8)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let nonce = GenericArray::from_slice(&n); //192bit (24 byte) nonce
        let cipher_text = cipher.encrypt(nonce, plaintext.as_bytes())?;
        let h_cipher = hex::encode(cipher_text);
        let h_nonce = hex::encode(n);
        Ok(h_nonce + &h_cipher)
    }

    ///Encrypt given data string, returns ciphertext & nounce
    ///Prepends ciphertext with nounce
    ///Panics if chacha key is not 32 chars long
    fn decrypt(ciphertext: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let nx = &ciphertext[0..48];
        let datan = &ciphertext[48..];
        let data = hex::decode(datan)?;
        let n = hex::decode(nx)?;
        let key = GenericArray::from_slice(key.as_bytes());
        let cipher = XChaCha20Poly1305::new(key);
        let nonce = GenericArray::from_slice(&n); //96bit (12 byte) nonce
        let decrypted = cipher.decrypt(nonce, data.as_slice())?;
        Ok(String::from_utf8(decrypted)?)
    }
}