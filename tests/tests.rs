#[cfg(test)]
mod tests {
    use std::iter;

    use easy_aes::aead::aes256_gcm_siv::EasyAES;
    use easy_aes::aead::x_chacha20_poly1305::EasyXChaCha20Poly1305;
    use easy_aes::aead::EasyCryptoAead;
    use rand::distributions::Alphanumeric;
    use rand::Rng;
    use rayon::iter::ParallelIterator;
    use rayon::prelude::{IntoParallelIterator, IntoParallelRefIterator};

    type Key = String;
    type PlainText = String;
    const NUMBER_OF_TESTS: u64 = 2u64.pow(8);

    fn generate_tests() -> Vec<(PlainText, Key)> {
        let tests: Vec<(PlainText, Key)> = (0..NUMBER_OF_TESTS)
            .into_par_iter()
            .map(|_| {
                let rng = rand::thread_rng();
                let tx = iter::repeat(())
                    .map(|()| rng.clone().sample(Alphanumeric))
                    .map(char::from)
                    .take(rng.clone().gen::<u16>() as usize)
                    .collect::<String>();
                let tk = iter::repeat(())
                    .map(|()| rng.clone().sample(Alphanumeric))
                    .map(char::from)
                    .take(32)
                    .collect::<String>();
                (tx, tk)
            })
            .collect();
        tests
    }

    #[test]
    fn test_aes() {
        let tests = generate_tests();
        assert!(tests.par_iter().all(|testcase| {
            let encrypted = EasyAES::encrypt(&testcase.0, &testcase.1).unwrap();
            let decrypted = EasyAES::decrypt(&encrypted, &testcase.1).unwrap();
            testcase.0 == decrypted
        }));
    }

    #[test]
    fn test_xchacha20_poly1305() {
        let tests = generate_tests();
        assert!(tests.par_iter().all(|testcase| {
            let encrypted = EasyXChaCha20Poly1305::encrypt(&testcase.0, &testcase.1).unwrap();
            let decrypted = EasyXChaCha20Poly1305::decrypt(&encrypted, &testcase.1).unwrap();
            testcase.0 == decrypted
        }));
    }
}
