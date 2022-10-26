use blst::{
    blst_fr, blst_fr_add, blst_fr_eucl_inverse, blst_fr_mul, blst_fr_sub, blst_p2, blst_p2_add,
    blst_p2_mult, blst_scalar, blst_scalar_from_fr, min_pk as blst_core,
};
use blst_core::{SecretKey, Signature};
use std::collections::HashSet;

use crate::{
    conv::*,
    poly::{FeldmanVerifier, Polynomial},
    Error,
};

/// Shamir’s Secret Sharing
#[derive(Debug, Copy, Clone)]
pub struct Shamir {
    threshold: u32,
    limit: u32,
}

#[derive(Debug, Clone)]
pub struct ShamirShare<T> {
    pub id: u32,
    pub value: T,
}

pub type SecretKeyShare = ShamirShare<SecretKey>;
pub type SignatureShare = ShamirShare<Signature>;

/// The y coordinate of a point (x, y = f(x)) on the polynomial
trait TYCoordinate {
    /// f(0) += y[j] * l[j](0)
    fn add_assign_after_mul(&mut self, yj: &Self, lj0: &blst_fr);
}

impl TYCoordinate for blst_fr {
    fn add_assign_after_mul(&mut self, yj: &Self, lj0: &blst_fr) {
        let mut prod = blst_fr::default();
        unsafe {
            blst_fr_mul(&mut prod, yj, lj0);
            blst_fr_add(self, self, &prod);
        }
    }
}

impl TYCoordinate for blst_p2 {
    fn add_assign_after_mul(&mut self, yj: &Self, lj0: &blst_fr) {
        let mut prod = blst_p2::default();
        let mut t = blst_scalar::default();
        unsafe {
            blst_scalar_from_fr(&mut t, lj0);
            blst_p2_mult(&mut prod, yj, t.b.as_ptr(), SUB_GROUP_ORDER_BITS);
            blst_p2_add(self, self, &prod);
        }
    }
}

impl Shamir {
    /// Creates a shamir struct to share a secret key and recover this secret key and signatures
    pub fn create(threshold: u32, limit: u32) -> Result<Self, Error> {
        if threshold <= 1 || threshold > limit {
            return Err(Error::InvalidThresholdParameters);
        }
        Ok(Shamir { threshold, limit })
    }

    pub fn threshold(&self) -> u32 {
        return self.threshold;
    }
    pub fn limit(&self) -> u32 {
        return self.limit;
    }

    pub fn split(&self, sk: &SecretKey) -> (Vec<SecretKeyShare>, FeldmanVerifier) {
        let fr = sk.to_raw_value();
        let mut poly = Polynomial::new();
        poly.init(fr, self.threshold);

        let mut shares: Vec<SecretKeyShare> = Vec::new();
        // id must not be zero
        for id in 1..=self.limit {
            let fr_i = poly.eval_u32(id);
            let sk = SecretKey::from_raw_value(&fr_i).unwrap();
            shares.push(SecretKeyShare { id: id, value: sk });
        }

        (shares, poly.verifier())
    }

    /// Langrange interpolation
    /// T can be blst_fr or blst_p2
    ///
    /// Reference:
    ///     https://github.com/status-im/nim-blscurve/blob/master/blscurve/blst/blst_recovery.nim
    ///     https://github.com/dashpay/dips/blob/master/dip-0006/bls_m-of-n_threshold_scheme_and_dkg.md
    fn interpolate<T>(xs: Vec<blst_fr>, ys: Vec<T>) -> Result<T, Error>
    where
        T: TYCoordinate + Default + Copy,
    {
        let k = xs.len();
        if k == 0 || k != ys.len() {
            return Err(Error::InvalidInput);
        }

        if k == 1 {
            return Ok(ys[0]);
        }

        // We calculate L(0) so we can simplify
        // (X - X[0]) * (X - X[1]) .. (X - X[k]) to just X[0] * X[1] .. X[k]
        // Later we can divide by X[i] for each basis polynomial l[j](0)
        let mut a = xs[0];
        for i in 1..k {
            // a.mul_assign(&xs[i]);
            unsafe {
                blst_fr_mul(&mut a, &a, &xs[i]);
            }
        }

        let mut r = T::default();
        for j in 0..k {
            let mut b = xs[j];
            for i in 0..k {
                if i != j {
                    // b.mul_assign_after_sub(&xs[j], &xs[i]);
                    let mut diff = blst_fr::default();
                    unsafe {
                        blst_fr_sub(&mut diff, &xs[i], &xs[j]);
                        blst_fr_mul(&mut b, &b, &diff);
                    }
                }
            }
            // The j-th basis polynomial for X = 0, l[j](0) = a / b
            let mut lj0 = blst_fr::default();
            let mut b_inverted = blst_fr::default();
            unsafe {
                blst_fr_eucl_inverse(&mut b_inverted, &b);
                blst_fr_mul(&mut lj0, &a, &b_inverted);
            }

            r.add_assign_after_mul(&ys[j], &lj0);
        }
        Ok(r)
    }
}

/// The macro to implement recover_***
macro_rules! recover_impl {
    (
        $func_name: ident,
        $share_type: ty,
        $share_raw_type: ty
    ) => {
        impl Shamir {
            pub fn $func_name(
                &self,
                shares: &[ShamirShare<$share_type>],
            ) -> Result<$share_type, Error> {
                if shares.len() < self.threshold as usize {
                    return Err(Error::NotEnoughShares);
                }

                let mut xs: Vec<blst_fr> = Vec::new();
                let mut ys: Vec<$share_raw_type> = Vec::new();
                let mut idset: HashSet<u32> = HashSet::new();

                for share in shares {
                    if idset.contains(&share.id) {
                        return Err(Error::DuplicateShares);
                    }
                    idset.insert(share.id);
                    xs.push(u32_to_fr(share.id));
                    ys.push(share.value.to_raw_value());
                }

                match Self::interpolate(xs, ys) {
                    Ok(fr) => <$share_type>::from_raw_value(&fr),
                    Err(e) => Err(e),
                }
            }
        }
    };
}

recover_impl!(recover_secret, SecretKey, blst_fr);
recover_impl!(recover_signature, Signature, blst_p2);
