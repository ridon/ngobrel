package id.ridon.ngobrel.core;

import java.security.SignatureException;

public final class Signature {
  final byte[] sig;

  /**
   * Creates a new Signature
   * @param seq A byte sequence containing the signature value
   */
  Signature(byte[] seq) throws SignatureException {
    if (seq.length != 64) {
      throw new SignatureException("Signature raw size invalid");
    }
    sig = seq.clone();
  }

  /**
   * Returns a byte sequence containing the raw data of the signature
   * @return A byte sequence
   */
  public final byte[] getBytes() {
    return sig;
  }


}
