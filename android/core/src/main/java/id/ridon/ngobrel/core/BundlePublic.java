package id.ridon.ngobrel.core;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

public class BundlePublic {
  public final PublicKey identity;
  public final SignedPreKeyPublic spk;
  Map<PreKeyId, PublicKey> preKeys = new HashMap<>();

  public BundlePublic(PublicKey identity, SignedPreKeyPublic spk) {
    this.identity = identity;
    this.spk = spk;
  }

  public void insert(PreKeyId id, PublicKey key) {
    preKeys.put(id, key);
  }

  public PreKey pop() throws NullPointerException {
    Set<PreKeyId> keyIds = preKeys.keySet();
    Iterator<PreKeyId> it = keyIds.iterator();
    if (it.hasNext()) {
      PreKeyId id = it.next();
      PublicKey k = preKeys.get(id);
      PreKey retval = new PreKey(id, k);

      preKeys.remove(id);
      return retval;
    }
    throw new NullPointerException();
  }

  public PreKey fetch(PreKeyId preKeyId) {
    PublicKey k = preKeys.get(preKeyId);
    if (k == null) {
      return null;
    }

    PreKey retval = new PreKey(preKeyId, k);
    preKeys.remove(preKeyId);
    return retval;
  }

  public boolean equals(BundlePublic other) {
    return identity.equals(other.identity);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other) {
      return true;
    }
    if (other == null) {
      return false;
    }
    if (getClass() != other.getClass()) {
      return false;
    }
    return equals((BundlePublic)other);
  }

  public boolean verify() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
    return spk.verify(identity);
  }

  public byte[] encode() {
    int len = 33 + 97 + // identity + spk
        4 + // prekeys.size
        (preKeys.size() * (33 + 32)); // prekeys
    byte[] result = new byte[len];

    int offset = 0;
    System.arraycopy(identity.encode(), 0, result, offset, 33);
    offset += 33;
    System.arraycopy(spk.encode(), 0, result, offset, 97);
    offset += 97;
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.putInt(preKeys.size());
    System.arraycopy(buffer.array(), 0, result, offset, 4);
    offset += 4;

    Set<PreKeyId> keyIds = preKeys.keySet();
    Iterator<PreKeyId> it = keyIds.iterator();
    while (it.hasNext()) {
      PreKeyId id = it.next();
      PublicKey k = preKeys.get(id);

      System.arraycopy(id.raw(), 0, result, offset, 32);
      offset += 32;
      System.arraycopy(k.encode(), 0, result, offset, 33);
      offset += 33;
    }
    return  result;
  }

  public static final BundlePublic decode(byte[] raw) throws IllegalDataSizeException, InvalidKeyException, SignatureException {
    int offset = 0;
    PublicKey identity = PublicKey.decode(raw, offset);
    offset += 33;
    SignedPreKeyPublic spk = SignedPreKeyPublic.decode(raw, offset);
    offset += 97;

    BundlePublic bp = new BundlePublic(identity, spk);
    ByteBuffer b = ByteBuffer.wrap(raw, offset, 4);
    int len = b.getInt();
    offset += 4;
    for (int i = 0; i < len; i ++) {
      byte[] preKeyId = new byte[32];
      System.arraycopy(raw, offset, preKeyId, 0, 32);
      offset += 32;
      bp.insert(new PreKeyId(preKeyId), PublicKey.decode(raw, offset));
      offset += 33;
    }
    return bp;
  }
}