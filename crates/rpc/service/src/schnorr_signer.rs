use ark_ff::{BigInteger, PrimeField};
use bitcoin::{
    TapNodeHash,
    key::{Keypair, TapTweak},
};
use mosaic_vs3::Scalar;
use secp256k1::{Message, SECP256K1, hashes::Hash, schnorr::Signature};

pub(crate) struct SchnorrSigner(Keypair);

impl SchnorrSigner {
    pub(crate) fn from_ark_scalar(s: &Scalar) -> Self {
        let bytes: [u8; 32] = s
            .into_bigint()
            .to_bytes_be()
            .try_into()
            .expect("Fr is 32 bytes");
        let keypair = Keypair::from_seckey_slice(SECP256K1, &bytes).expect("valid secret key");
        Self(keypair)
    }

    pub(crate) fn sign(self, digest: [u8; 32], tweak: Option<[u8; 32]>) -> Signature {
        let tweak = tweak.map(|h| TapNodeHash::from_slice(&h).expect("guaranteed correct length"));

        self.0
            .tap_tweak(SECP256K1, tweak)
            .to_keypair()
            .sign_schnorr(Message::from_digest_slice(&digest).expect("digest is 32 bytes"))
    }
}
