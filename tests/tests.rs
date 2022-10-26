use blst::min_pk as blst_core;
use blst_core::SecretKey;

use rand::Rng;
use tbls::*;

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";

fn random_sk() -> SecretKey {
    let rng = &mut rand::thread_rng();
    let ikm: [u8; 32] = rng.gen();
    SecretKey::key_gen(&ikm, &[]).unwrap()
}

#[test]
fn test_verification() {
    let shamir = Shamir::create(6, 10).unwrap();
    let sk = random_sk();
    let (shares, verifier) = shamir.split(&sk);

    for share in shares.iter() {
        assert!(verifier.verify(share.id, &share.value))
    }
}

#[test]
fn test_recover_secret_key() {
    let shamir = Shamir::create(6, 10).unwrap();
    let sk = random_sk();
    let (shares, _) = shamir.split(&sk);

    let sk_r1 = shamir.recover_secret(&shares).unwrap();
    assert_eq!(sk.to_bytes(), sk_r1.to_bytes());

    let sk_r2 = shamir.recover_secret(&shares[0..6]).unwrap();
    assert_eq!(sk.to_bytes(), sk_r2.to_bytes());
}
#[test]
fn test_recover_signature() {
    let shamir = Shamir::create(6, 10).unwrap();
    let sk = random_sk();
    let (sk_shares, _) = shamir.split(&sk);

    let msg: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5,
        6, 7,
    ];
    let sign = sk.sign(&msg, DST, &[]);

    let mut sign_shares: Vec<SignatureShare> = Vec::new();

    for sk_share in sk_shares.iter() {
        let sign = sk_share.value.sign(&msg, DST, &[]);
        sign_shares.push(SignatureShare {
            id: sk_share.id,
            value: sign,
        });
    }

    let sign_r1 = shamir.recover_signature(&sign_shares).unwrap();
    let sign_r2 = shamir.recover_signature(&sign_shares[0..6]).unwrap();

    assert_eq!(sign, sign_r1);
    assert_eq!(sign, sign_r2);
}
