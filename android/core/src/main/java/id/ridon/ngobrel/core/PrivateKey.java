package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.SignatureException;


public class PrivateKey extends Key {

  private final byte[] forSigning;

  public static final int SIZE = 64;
  public static final int ESIZE = SIZE + 1;


  PrivateKey() {
    key = new byte[Key.SIZE];
    forSigning = new byte[Key.SIZE];
  }

  PrivateKey(final byte[] key, final byte[] forSigning) throws IllegalDataSizeException {
    super(key);
    this.forSigning = forSigning;
  }

  /**
   * Signs a message
   * @param message The message to be signed
   * @return A byte array of the signature
   * @throws NoSuchAlgorithmException
   */
  public id.ridon.ngobrel.core.Signature sign(byte[] message) throws NoSuchAlgorithmException, SignatureException {

    boolean done = false;

    byte[] pubKey = new byte[Key.SIZE];
    Curve.keygen(pubKey, null, key);

    byte[] pubPoint = new byte[Key.SIZE];
    byte[] sig1 = new byte[0];
    byte[] sig2 = sig1.clone();
    while (!done) {
      SecureRandom random = new SecureRandom();
      byte[] privPoint = new byte[Key.SIZE];
      random.nextBytes(privPoint);
      Curve.keygen(pubPoint, null, privPoint);

      MessageDigest d1 = MessageDigest.getInstance("SHA-256");
      sig1 = d1.digest(pubPoint);

      MessageDigest d2 = MessageDigest.getInstance("SHA-256");
      d2.update(message);
      d2.update(pubKey);
      byte[] msgDigest = d2.digest();

      sig2 = new byte[Key.SIZE];
      done = Curve.sign(sig2, msgDigest, privPoint, forSigning);
    }

    byte[] sig = new byte[SIZE];
    System.arraycopy(sig1, 0, sig, 0, Key.SIZE);
    System.arraycopy(sig2, 0, sig, Key.SIZE, Key.SIZE);
    return new id.ridon.ngobrel.core.Signature(sig);
  }

  /**
   * Serializes the key
   * @return byte sequence containing serialized key
   */
  @Override
  public final byte[] encode() {
    byte[] retval = new byte[ESIZE];

    retval[0] = 0x5;
    System.arraycopy(key, 0, retval, 1, Key.SIZE);
    System.arraycopy(forSigning, 0, retval, Key.SIZE + 1, Key.SIZE);

    return retval;
  }
  /**
   * Decodes a raw data into a PrivateKey object
   * @param raw Raw data byte sequence
   * @param offset The offset of the data we want to inspect
   * @return a new PrivateKey object
   */
  public static PrivateKey decode(byte[] raw, int offset) throws InvalidKeyException, IllegalDataSizeException {
    if (raw[offset] == 0x5 && raw.length >= ESIZE + offset) {
      byte[] forSigning = new byte[Key.SIZE];
      System.arraycopy(raw, offset + Key.ESIZE, forSigning, 0, Key.SIZE);
      return new PrivateKey(Key.decode(raw, offset).raw(), forSigning);
    }
    throw new IllegalDataSizeException();
  }

  /**
   * Creates a shared secret from this private key and other public key
   * @param other The other public key
   * @return Byte sequence containing the shared secret
   */
  public final byte[] shareSecret(PublicKey other) {
    byte[] shared = new byte[Key.SIZE];
    byte[] k = key.clone();
    k[31] &= 0x7F;
    k[31] |= 0x40;
    k[ 0] &= 0xF8;
    Curve.curve(shared, k, other.raw());

    return shared;
  }

  /**
   * Derives a key from this private key and other public key
   * @param other The other public key
   * @param info The info string
   * @param length The length of the key
   * @return Byte sequence containing the derived key
   */
  public byte[] deriveKey(PublicKey other, String info, int length) {
    byte[] shared = shareSecret(other);

    byte[] salt = Constants.getRidonSalt512();
    Kdf kdf = Kdf.KdfSha512(shared, salt);
    byte[] kdfResult = kdf.get(info, length);
    return kdfResult;
  }

}
