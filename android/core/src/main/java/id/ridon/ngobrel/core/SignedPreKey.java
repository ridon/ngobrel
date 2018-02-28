package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * This class represents signed pre-keys
 */
public class SignedPreKey {

  final SignedPreKeyPublic pub;
  final PrivateKey priv;

  public SignedPreKey(PrivateKey key) throws IllegalDataSizeException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    KeyPair preKey = new KeyPair();

    Signature sig = key.sign(preKey.publicKey.encode());

    pub = new SignedPreKeyPublic(preKey.publicKey, sig);
    priv = preKey.privateKey;
  }

  public final SignedPreKeyPublic getPublic() {
    return pub;
  }

  public final PrivateKey getPrivateKey() {
    return priv;
  }
}
