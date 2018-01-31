package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * This class is a representation of public part of SignedPreKey
 */
public class SignedPreKeyPublic {
  public PublicKey publicKey;
  public Signature signature;

  /**
   * Creates a new SignedPreKeyPublic instance
   * @param pubKey The public key
   * @param sig The signature
   */
  SignedPreKeyPublic(PublicKey pubKey, Signature sig) throws SignatureException{
    publicKey = pubKey;
    signature = sig;
  }

  /**
   * Verifies a PublicKey against this SignedPreKey
   * @param pub The PublicKey to inspect
   * @return whether the public key is verified for this SignedPreKey
   */
  public boolean verify(PublicKey pub) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
    return pub.verify(publicKey.encode(), signature);
  }

  /**
   * Serialize a SignedPreKeyPublic
   * @return byte sequence containing serialized SignedPreKeyPublic
   */
  public byte[] encode() {
    int size = 33 + 64;
    byte[] ret = new byte[size];
    System.arraycopy(publicKey.encode(), 0, ret, 0, 33);
    System.arraycopy(signature.getBytes(), 0, ret, 33, 64);
    return ret;
  }

  public static SignedPreKeyPublic decode(byte[] raw, int offset) throws InvalidKeyException, IllegalDataSizeException, SignatureException {
    if (raw[offset] == 0x5 && raw.length >= (64 + 33) + offset) {
      PublicKey publicKey = PublicKey.decode(raw, offset);
      byte[] sig = new byte[64];
      System.arraycopy(raw, offset + 33, sig, 0, 64);
      SignedPreKeyPublic spk = new SignedPreKeyPublic(publicKey, new Signature(sig));

      return spk;
    }
    throw new IllegalDataSizeException();
  }
}