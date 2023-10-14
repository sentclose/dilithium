use rand_core::*;

pub fn randombytes<R>(x: &mut [u8], len: usize, rng: &mut R) -> Result<(), Error>
  where
      R: RngCore + CryptoRng,
{
  rng.try_fill_bytes(&mut x[..len])
}
