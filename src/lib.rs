use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use rand::Rng;
use std::error::Error;

///Encrypt given data string, returns ciphertext & nounce
///Prepends ciphertext with nounce
///Panics if aes key is not 32 chars long
pub fn encrypt(plaintext: &str, aes_key: &str) -> Result<String, Box<dyn Error>> {
    assert_eq!(aes_key.len(), 32);
    let mut rng = rand::thread_rng();
    let key = GenericArray::from_slice(aes_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let n = (0..(96 / 8)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    let nonce = GenericArray::from_slice(&n); //96bit (12 byte) nounce
    let cipher_text = cipher.encrypt(nonce, plaintext.as_bytes())?;
    let h_cipher = hex::encode(cipher_text);
    let h_nonce = hex::encode(n);
    Ok(h_nonce + &h_cipher)
}

///Decrypts given ciphertext using key & nounce, returns plaintext
///Reads nounce from first 24 chars of ciphertext
///Panics if aes key is not 32 chars long
pub fn decrypt(ciphertext: &str, aes_key: &str) -> Result<String, Box<dyn Error>> {
    assert_eq!(aes_key.len(), 32);
    let nx = &ciphertext[0..24];
    let datan = &ciphertext[24..];
    let data = hex::decode(datan)?;
    let n = hex::decode(nx)?;
    let key = GenericArray::from_slice(aes_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let nonce = GenericArray::from_slice(&n); //96bit (12 byte) nonce
    let decrypted = cipher.decrypt(nonce, data.as_slice())?;
    Ok(String::from_utf8(decrypted)?)
}

#[cfg(test)]
mod tests {
    use crate::{decrypt, encrypt};
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use std::iter;

    #[test]
    fn test_aes() {
        let mut rng = rand::thread_rng();
        for _i in 0..1024 {
            let tx = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric))
                .map(char::from)
                .take(1024)
                .collect::<String>();
            let tk = iter::repeat(())
                .map(|()| rng.sample(Alphanumeric)).map(char::from).take(32).collect::<String>();
            let encrypted = encrypt(&tx, &tk).unwrap();
            let decrypted = decrypt(&encrypted, &tk).unwrap();
            assert_eq!(tx, decrypted);
        }
    }
}
