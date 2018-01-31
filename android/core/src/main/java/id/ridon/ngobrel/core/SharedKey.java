package id.ridon.ngobrel.core;

public class SharedKey {
  public final byte[] key;
  public final PreKeyId preKeyId;

  SharedKey(final byte[] key, final PreKeyId preKeyId) {
    this.key = key;
    this.preKeyId = preKeyId;
  }
}
