use blst::{
    blst_bendian_from_scalar, blst_fr, blst_fr_from_scalar, blst_p1, blst_p1_affine,
    blst_p1_affine_compress, blst_p1_deserialize, blst_p1_from_affine, blst_p1_to_affine, blst_p2,
    blst_p2_affine, blst_p2_affine_compress, blst_p2_deserialize, blst_p2_from_affine,
    blst_p2_to_affine, blst_scalar, blst_scalar_from_bendian, blst_scalar_from_fr,
    blst_scalar_from_uint32, min_pk as blst_core,
};
use blst_core::{PublicKey, SecretKey, Signature};

use crate::Error;
/// The number of bits of the curve order
pub const SUB_GROUP_ORDER_BITS: usize = 255;

/// The byte-length of a BLS secret key.
pub const SECRET_KEY_BYTES_LEN: usize = 32;

/// The byte-length of a BLS public key when serialized in compressed form.
pub const PUBLIC_KEY_BYTES_LEN: usize = 48;

/// The byte-length of a BLS signature when serialized in compressed form.
pub const SIGNATURE_BYTES_LEN: usize = 96;

pub fn u32_to_scalar(x: u32) -> blst_scalar {
    let mut scalar = blst_scalar::default();
    let arr = [0, 0, 0, 0, 0, 0, 0, x];
    unsafe {
        blst_scalar_from_uint32(&mut scalar, arr.as_ptr());
    }
    scalar
}

pub fn u32_to_fr(x: u32) -> blst_fr {
    let mut fr = blst_fr::default();
    let scalar = u32_to_scalar(x);
    unsafe {
        blst_fr_from_scalar(&mut fr, &scalar);
    }
    fr
}

/// Blst structs keep underline `point` data private, but we need to use those points to perform cryptographic operations.
/// We use serialization and deserialization to do data type conversions according to the implementation in Blst library.
pub trait TBlstRawValue<T>: Sized {
    fn to_raw_value(&self) -> T;
    fn from_raw_value(raw: &T) -> Result<Self, Error>;
}

impl TBlstRawValue<blst_fr> for SecretKey {
    fn to_raw_value(&self) -> blst_fr {
        let mut scalar = blst_scalar::default();
        let mut fr = blst_fr::default();
        let sk_bytes = self.to_bytes();
        unsafe {
            blst_scalar_from_bendian(&mut scalar, sk_bytes.as_ptr());
            blst_fr_from_scalar(&mut fr, &scalar);
        }
        fr
    }

    fn from_raw_value(raw: &blst_fr) -> Result<Self, Error> {
        let mut scalar = blst_scalar::default();
        let mut bytes = [0; SECRET_KEY_BYTES_LEN];
        unsafe {
            blst_scalar_from_fr(&mut scalar, raw);
            blst_bendian_from_scalar(bytes.as_mut_ptr(), &scalar);
        }

        match SecretKey::from_bytes(&bytes) {
            Ok(sk) => Ok(sk),
            Err(e) => Err(Error::BlstError(e)),
        }
    }
}

impl TBlstRawValue<blst_p1> for PublicKey {
    fn to_raw_value(&self) -> blst_p1 {
        let mut p1 = blst_p1::default();
        let mut p1_af = blst_p1_affine::default();
        let bytes = self.to_bytes();
        unsafe {
            blst_p1_deserialize(&mut p1_af, bytes.as_ptr());
            blst_p1_from_affine(&mut p1, &p1_af);
        }
        p1
    }
    fn from_raw_value(raw: &blst_p1) -> Result<Self, Error> {
        let mut p1_af = blst_p1_affine::default();
        let mut bytes = [0; PUBLIC_KEY_BYTES_LEN];
        unsafe {
            blst_p1_to_affine(&mut p1_af, raw);
            blst_p1_affine_compress(bytes.as_mut_ptr(), &p1_af);
        }

        match PublicKey::from_bytes(&bytes) {
            Ok(pk) => Ok(pk),
            Err(e) => Err(Error::BlstError(e)),
        }
    }
}

impl TBlstRawValue<blst_p2> for Signature {
    fn to_raw_value(&self) -> blst_p2 {
        let mut p2 = blst_p2::default();
        let mut p2_af = blst_p2_affine::default();
        let bytes = self.to_bytes();
        unsafe {
            blst_p2_deserialize(&mut p2_af, bytes.as_ptr());
            blst_p2_from_affine(&mut p2, &p2_af);
        }
        p2
    }

    fn from_raw_value(raw: &blst_p2) -> Result<Self, Error> {
        let mut p2_af = blst_p2_affine::default();
        let mut bytes = [0; SIGNATURE_BYTES_LEN];
        unsafe {
            blst_p2_to_affine(&mut p2_af, raw);
            blst_p2_affine_compress(bytes.as_mut_ptr(), &p2_af);
        }

        match Signature::from_bytes(&bytes) {
            Ok(sk) => Ok(sk),
            Err(e) => Err(Error::BlstError(e)),
        }
    }
}
