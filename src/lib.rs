use aes_gcm_siv::Aes256GcmSiv;
use aes_gcm_siv::aead::generic_array::GenericArray;
use aes_gcm_siv::aead::{NewAead, Aead};
use rand::Rng;

///Encrypt given data string, returns ciphertext & nounce
///Prepends ciphertext with nounce
pub fn encrypt(plaintext: &str, aes_key: &str) -> String {
    assert_eq!(aes_key.len(), 32);
    let mut rng = rand::thread_rng();
    let key = GenericArray::from_slice(aes_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let n = (0..(96/8)).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
    let nonce= GenericArray::from_slice(&n);    //96bit (12 byte) nounce
    let cipher_text = cipher.encrypt(nonce, plaintext.as_bytes()).expect(&format!("{}", obfstr::obflocal!("Couldn't encrypt")));
    let h_cipher = hex::encode(cipher_text);
    let h_nonce = hex::encode(n);
    h_nonce + &h_cipher
}

///Decrypts given ciphertext using key & nounce, returns plaintext
///Reads nounce from first 24 chars of ciphertext
pub fn decrypt(ciphertext: &str, aes_key: &str) -> String{
    assert_eq!(aes_key.len(), 32);
    let nx = &ciphertext[0..24];
    let datan = &ciphertext[24..];
    let data = hex::decode(datan).expect(&format!("{}", obfstr::obflocal!("Couldn't decode hex")));
    let n = hex::decode(nx).expect(&format!("{}", obfstr::obflocal!("Couldn't decode hex")));
    let key = GenericArray::from_slice(aes_key.as_bytes());
    let cipher = Aes256GcmSiv::new(key);
    let nonce= GenericArray::from_slice(&n);    //96bit (12 byte) nonce
    let decrypted = cipher.decrypt(nonce, data.as_slice()).expect(&format!("{}", obfstr::obflocal!("Couldn't decrypt")));
    String::from_utf8(decrypted).expect(&format!("{}", obfstr::obflocal!("Couldn't get string")))
}

#[cfg(test)]
mod tests {
    use crate::{encrypt, decrypt};
    use rand::Rng;
    use rand::distributions::Alphanumeric;
    use rayon::prelude::IntoParallelIterator;

    #[test]
    fn it_works() {
        let mut rng = rand::thread_rng();
        for i in 0..1024 {
            let tx = rng.sample_iter(&Alphanumeric).take(1024).collect::<String>();
            let tk = rng.sample_iter(&Alphanumeric).take(32).collect::<String>();
            let encrypted = encrypt(&tx, &tk);
            let decrypted = decrypt(&encrypted, &tk);
            assert_eq!(tx, decrypted);
        }
    }
}
