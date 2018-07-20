package id.ngobrel.core;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Random;

public final class KeyPair {
  public final PrivateKey privateKey;
  public final id.ngobrel.core.PublicKey publicKey;


  public KeyPair() throws IllegalDataSizeException {
    Random r = new SecureRandom();
    byte[] priv = new byte[32];
    r.nextBytes(priv);

    byte[] pubKey = new byte[32];
    byte[] privSignature = new byte[32];
    Curve.keygen(pubKey, privSignature, priv);
    privateKey = new PrivateKey(priv, privSignature);
    publicKey = new id.ngobrel.core.PublicKey(pubKey);
  }

  public KeyPair(final PrivateKey privateKey, final id.ngobrel.core.PublicKey publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  public byte[] encode() throws IOException {
    ByteArrayOutputStream ss = new ByteArrayOutputStream();
    ss.write(privateKey.encode());
    ss.write(publicKey.encode());
    return ss.toByteArray();
  }

  public static KeyPair decode(final byte[] raw) throws InvalidKeyException, IOException, IllegalDataSizeException {
    PrivateKey privateKey = PrivateKey.decode(raw, 0);
    id.ngobrel.core.PublicKey publicKey = id.ngobrel.core.PublicKey.decode(raw, 65);
    return new KeyPair(privateKey, publicKey);
  }

  @Override
  public boolean equals(Object other) {
    return ((KeyPair)other).privateKey.equals(privateKey) &&
        ((KeyPair)other).publicKey.equals(publicKey);
  }
}
