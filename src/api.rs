use rand_core::{CryptoRng, Error, RngCore};
use crate::params::{PUBLICKEYBYTES, SECRETKEYBYTES, SIGNBYTES};
use crate::sign::*;

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct Keypair {
  pub public: [u8; PUBLICKEYBYTES],
  pub secret: [u8; SECRETKEYBYTES],
}

pub enum SignError {
  Input,
  Verify,
}

impl Keypair {

  pub fn expose_secret(&self) -> &[u8] {
    &self.secret
  }

  pub fn generate<R>(rng: &mut R) -> Result<Keypair, Error>
    where
        R: RngCore + CryptoRng,
  {
    let mut public = [0u8; PUBLICKEYBYTES];
    let mut secret = [0u8; SECRETKEYBYTES];
    crypto_sign_keypair(&mut public, &mut secret, None,rng)?;
   Ok( Keypair { public, secret })
  }


  pub fn sign<R>(&self, msg: &[u8], rng: &mut R) ->Result< [u8; SIGNBYTES], Error>
    where
        R: RngCore + CryptoRng,
  {
    let mut sig = [0u8; SIGNBYTES];
    crypto_sign_signature(&mut sig, msg, &self.secret,rng)?;
    Ok(sig)
  }
}

pub fn verify(
  sig: &[u8],
  msg: &[u8],
  public_key: &[u8],
) -> Result<(), SignError> {
  if sig.len() != SIGNBYTES {
    return Err(SignError::Input);
  }
  crypto_sign_verify(&sig, &msg, public_key)
}

pub fn sign<R>(msg: &[u8], rng: &mut R, sign_key: &[u8])->Result< [u8; SIGNBYTES], Error>
  where
      R: RngCore + CryptoRng,
{
  let mut sig = [0u8; SIGNBYTES];
  crypto_sign_signature(&mut sig, msg, sign_key,rng)?;

  Ok(sig)
}