package id.ngobrel.core;

/**
 * This class represents a PreKey
 */
public class PreKey {
  public final PublicKey publicKey;
  public final PreKeyId keyId;

  public PreKey(final PreKeyId keyId, final PublicKey publicKey) {
    this.keyId = keyId;
    this.publicKey = publicKey;
  }
}
