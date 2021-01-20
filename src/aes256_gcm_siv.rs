use crate::EasyCryptoAead;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::Aead;
use aes_gcm_siv::aead::NewAead;
use aes_gcm_siv::Aes256GcmSiv;
use rand::Rng;
use std::error::Error;

pub struct EasyAES {}
impl EasyCryptoAead for EasyAES {
    ///Encrypt given data string, returns ciphertext & nounce
    ///Prepends ciphertext with nounce
    ///Panics if aes key is not 32 chars long
    fn encrypt(plaintext: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let mut rng = rand::thread_rng();
        let key = GenericArray::from_slice(key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let n = (0..(96 / 8)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let nonce = GenericArray::from_slice(&n); //96bit (12 byte) nonce
        let cipher_text = cipher.encrypt(nonce, plaintext.as_bytes())?;
        let h_cipher = hex::encode(cipher_text);
        let h_nonce = hex::encode(n);
        Ok(h_nonce + &h_cipher)
    }

    ///Decrypts given ciphertext using key & nounce, returns plaintext
    ///Reads nounce from first 24 chars of ciphertext
    ///Panics if aes key is not 32 chars long
    fn decrypt(ciphertext: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let nx = &ciphertext[0..24];
        let datan = &ciphertext[24..];
        let data = hex::decode(datan)?;
        let n = hex::decode(nx)?;
        let key = GenericArray::from_slice(key.as_bytes());
        let cipher = Aes256GcmSiv::new(key);
        let nonce = GenericArray::from_slice(&n); //96bit (12 byte) nonce
        let decrypted = cipher.decrypt(nonce, data.as_slice())?;
        Ok(String::from_utf8(decrypted)?)
    }
}
