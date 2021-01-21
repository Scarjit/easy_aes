use crate::custom_aead::EasyCryptoCustomAEAD;
use std::error::Error;
use salsa20::{Key, Nonce, Salsa20};
use rand::Rng;
use salsa20::cipher::{NewStreamCipher, SyncStreamCipher};

pub struct EasySalsa20Kangerootwelve {}
impl EasyCryptoCustomAEAD for EasySalsa20Kangerootwelve {
    fn encrypt(input: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let mut rng = rand::thread_rng();
        let key = Key::from_slice(key.as_bytes());
        let n = (0..(96 / 12)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let nonce = Nonce::from_slice(&n); //96bit (12 byte) nonce

        let mut cipher = Salsa20::new(&key, &nonce);
        let mut data = input.as_bytes().to_vec();
        cipher.apply_keystream(&mut data);

        let h_cipher = hex::encode(data);
        let h_nonce = hex::encode(n);
        Ok(h_nonce + &h_cipher)
    }

    fn decrypt(input: &str, key: &str) -> Result<String, Box<dyn Error>> {
        assert_eq!(key.len(), 32);
        let nx = &input[0..16];
        let datan = &input[16..];
        let mut data = hex::decode(datan)?;
        let n = hex::decode(nx)?;
        let nonce = Nonce::from_slice(&n); //96bit (12 byte) nonce

        let key = Key::from_slice(key.as_bytes());
        let mut cipher = Salsa20::new(&key, &nonce);
        cipher.apply_keystream(&mut data);
        Ok(String::from_utf8(data)?)
    }
}
