use digest::{Digest, FixedOutput};
use k256::ecdsa::signature::DigestSigner;
use k256::ecdsa::signature::DigestVerifier;
use k256::ecdsa::signature::Signature as Sig;
use k256::ecdsa::{SigningKey, VerifyingKey};
use k256::elliptic_curve::sec1::{Tag, ToEncodedPoint};
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;

use primitive_types::{H256, H512};
use crate::error::Error;

pub const SECRET_KEY_LENGTH: usize = 32;
pub const PUBLIC_KEY_LENGTH: usize = 65;
pub const SIG_KEY_LENGTH: usize = 65;
pub const KEYPAIR_KEY_LENGTH: usize = SECRET_KEY_LENGTH + PUBLIC_KEY_LENGTH;

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct Keypair {
    pub secret: SecretKey,
    pub public: PublicKey,
}

impl Keypair {
    pub fn generate<T>(csprng: &mut T) -> Self
        where
            T: CryptoRng + RngCore,
    {
        let secret = SecretKey::generate(csprng);
        let public = secret.public();
        Self { secret, public }
    }

    pub fn from_bytes<B: AsRef<[u8]>>(bytes: B) -> Result<Self, Error> {
        let secret = SecretKey::from_bytes(bytes.as_ref())?;
        let public = secret.public();
        Ok(Self { secret, public })
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct SecretKey {
    inner: SigningKey,
}

impl SecretKey {
    pub fn generate<T>(csprng: &mut T) -> SecretKey
        where
            T: CryptoRng + RngCore,
    {
        Self {
            inner: SigningKey::random(csprng),
        }
    }
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let inner = SigningKey::from_bytes(bytes)?;
        Ok(SecretKey { inner })
    }

    pub fn sign(&self, msg: &[u8]) -> Result<Signature, Error> {
        let mut prehash = Sha256::default();
        prehash.update(msg);
        let sig = self.inner.sign_digest(prehash);
        Ok(Signature { inner: sig })
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; SECRET_KEY_LENGTH] {
        let mut secret_key = [0_u8; SECRET_KEY_LENGTH];
        secret_key.copy_from_slice(self.inner.to_bytes().as_slice());
        secret_key
    }

    pub fn hash(&self) -> H256 {
        H256::from(self.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        PublicKey {
            inner: self.inner.verifying_key(),
        }
    }
}

#[derive(Eq, PartialEq, Clone, Debug)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let inner = VerifyingKey::from_sec1_bytes(bytes)?;
        Ok(Self { inner })
    }

    #[inline]
    pub fn from_fixed_bytes(bytes: &H512) -> Result<Self, Error> {
        let raw_bytes = [[Tag::Uncompressed as u8].as_slice(), bytes.as_bytes()].concat();
        let inner = VerifyingKey::from_sec1_bytes(raw_bytes.as_slice())?;
        Ok(Self { inner })
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LENGTH] {
        let encoded_pk = self.inner.to_encoded_point(false);
        let mut pub_key = [0_u8; PUBLIC_KEY_LENGTH];
        pub_key.copy_from_slice(encoded_pk.as_bytes());
        pub_key
    }

    #[inline]
    pub fn to_fixed_bytes(&self) -> H512 {
        let encoded_pk = self.inner.to_encoded_point(false);
        let pub_key = H512::from_slice(&encoded_pk.as_bytes()[1..]);
        pub_key
    }

    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<(), Error> {
        let mut prehash = Sha256::default();
        prehash.update(msg);
        self.inner
            .verify_digest(prehash, &sig.inner)
            .map_err(|e| e.into())
    }

    pub fn hash(&self) -> H256 {
        let encoded_pk = self.inner.to_encoded_point(false);
        let mut hasher = sha3::Sha3_256::default();
        hasher.update(encoded_pk);
        let out = hasher.finalize_fixed();
        H256::from_slice(&out[..])
    }
}

#[derive(Eq, PartialEq, Copy, Clone)]
pub struct Signature {
    inner: k256::ecdsa::recoverable::Signature,
}

impl Signature {
    #[inline]
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let sig = k256::ecdsa::recoverable::Signature::from_bytes(bytes)?;
        Ok(Self { inner: sig })
    }

    #[inline]
    pub fn from_rsv<B: AsRef<[u8]>>(rsv: (B, B, u8)) -> Result<Self, Error> {
        if rsv.0.as_ref().len() != 32_usize {
            return Err(Error::RSVInvalid);
        }
        if rsv.1.as_ref().len() != 32_usize {
            return Err(Error::RSVInvalid);
        }

        let mut bytes = [0_u8; SIG_KEY_LENGTH];
        bytes[..32].copy_from_slice(rsv.0.as_ref());
        bytes[32..64].copy_from_slice(rsv.1.as_ref());
        bytes[64] = rsv.2;
        let sig = k256::ecdsa::recoverable::Signature::from_bytes(&bytes)?;
        Ok(Self { inner: sig })
    }

    #[inline]
    pub fn to_bytes(&self) -> [u8; SIG_KEY_LENGTH] {
        let mut sig = [0_u8; SIG_KEY_LENGTH];
        sig.copy_from_slice(self.inner.as_bytes());
        sig
    }

    pub fn recover_public_key(&self, msg: &[u8]) -> Result<PublicKey, Error> {
        let mut prehash = Sha256::default();
        prehash.update(msg);
        let pk = self.inner.recover_verifying_key_from_digest(prehash)?;
        Ok(PublicKey { inner: pk })
    }

    pub fn rsv(&self) -> (H256, H256, u8) {
        let mut r = [0_u8; 32];
        r.copy_from_slice(&self.inner.as_bytes()[..32]);
        let mut s = [0_u8; 32];
        s.copy_from_slice(&self.inner.as_bytes()[32..64]);
        let v = self.inner.as_bytes()[64];
        (H256::from(r), H256::from(s), v)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand_chacha::ChaCha20Rng;
    use rand_core::SeedableRng;

    #[test]
    fn test_pair_derivation() {
        let mut csprng = ChaCha20Rng::from_entropy();
        let secret = SecretKey::generate(&mut csprng);
        let public = secret.public();

        let derived_pub = PublicKey::from_bytes(&public.to_bytes()).unwrap();
        let derived_secret = SecretKey::from_bytes(&secret.to_bytes()).unwrap();
        let derived_pub_2 = derived_secret.public();

        assert_eq!(public, derived_pub);
        assert_eq!(public, derived_pub_2);
        assert_eq!(secret, derived_secret);
    }

    #[test]
    fn test_signing_and_recovery() {
        let mut csprng = ChaCha20Rng::from_entropy();
        let secret = SecretKey::generate(&mut csprng);
        let public = secret.public();
        let sig = secret.sign(b"Hello").unwrap();
        let derived_sig = Signature::from_bytes(&sig.to_bytes()).unwrap();
        let derived_pub = derived_sig.recover_public_key(b"Hello").unwrap();
        assert!(public.verify(b"Hello", &sig).is_ok());
        assert_eq!(derived_pub, public);
        let rsv_derived = Signature::from_rsv(sig.rsv()).unwrap();
        let rsv_pubkey = rsv_derived.recover_public_key(b"Hello").unwrap();
        assert_eq!(rsv_pubkey, public);
    }
}