use crate::conv::{u32_to_fr, u32_to_scalar, TBlstRawValue, SUB_GROUP_ORDER_BITS};
use blst::{
    blst_fr, blst_fr_add, blst_fr_mul, blst_p1, blst_p1_add, blst_p1_mult, min_pk::SecretKey,
};
use rand::Rng;

/// Polynomials in Shamir’s Secret Sharing are generally of the following form:
///     y = f(x) =a[0] + a[1]x + a[2]x^2 + a[3]x^3 + ... + a[k-1]x^[k-1]
/// This structure stores all coefficients a[i]
#[derive(Debug, Clone)]
pub struct Polynomial {
    /// coefficients
    cfs: Vec<blst_fr>,
}

impl Polynomial {
    pub fn new() -> Self {
        let cfs = Vec::new();
        Self { cfs }
    }

    fn rand_fr() -> blst_fr {
        let rng = &mut rand::thread_rng();
        let ikm: [u8; 32] = rng.gen();
        let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
        sk.to_raw_value()
    }

    /// Initializes a polynomial
    /// y = f(x) =a[0] + a[1]x + a[2]x^2 + a[3]x^3 + ... + a[k-1]x^[k-1]
    pub fn init(&mut self, a0: blst_fr, k: u32) {
        self.cfs.push(a0);
        let mut i = 1;
        while i < k {
            let fr = Polynomial::rand_fr();
            self.cfs.push(fr);
            i += 1;
        }
    }

    /// Evaluates the polynomial at point x
    pub fn eval(&self, x: blst_fr) -> blst_fr {
        let count = self.cfs.len();
        if count == 0 {
            return blst_fr::default();
        } else if count == 1 {
            return self.cfs[0];
        }

        // Horner's method
        // We will calculate a[0] + X*(a[1] + X*(a[2] + .. + X*(a[n-1]  + X*a[n]))
        let mut out = self.cfs[count - 1];
        for i in (0..=count - 2).rev() {
            unsafe {
                blst_fr_mul(&mut out, &out, &x);
                blst_fr_add(&mut out, &out, &self.cfs[i]);
            }
        }
        out
    }

    pub fn eval_u32(&self, x: u32) -> blst_fr {
        self.eval(u32_to_fr(x))
    }

    pub fn verifier(&self) -> FeldmanVerifier {
        let mut commitments = Vec::new();
        let count = self.cfs.len();
        if count == 0 {
            commitments.push(blst_p1::default());
        } else {
            for cf in self.cfs.iter() {
                let sk = SecretKey::from_raw_value(cf).unwrap();
                let pk = sk.sk_to_pk();
                commitments.push(pk.to_raw_value());
            }
        }
        FeldmanVerifier { commitments }
    }
}

/// The commitments compose the public key polynomial
pub struct FeldmanVerifier {
    pub commitments: Vec<blst_p1>,
}

impl FeldmanVerifier {
    /// Verifies the received secret key share
    pub fn verify(&self, id: u32, sk_share: &SecretKey) -> bool {
        let count = self.commitments.len();
        if count < 1 {
            return false;
        }

        let pk_share = sk_share.sk_to_pk().to_raw_value();

        // Evaluates the public key polynomial P(x)
        let x = u32_to_scalar(id);
        let mut pk = self.commitments[count - 1];
        for i in (0..=count - 2).rev() {
            unsafe {
                blst_p1_mult(&mut pk, &pk, x.b.as_ptr(), SUB_GROUP_ORDER_BITS);
                blst_p1_add(&mut pk, &pk, &self.commitments[i]);
            }
        }

        pk_share == pk
    }
}
