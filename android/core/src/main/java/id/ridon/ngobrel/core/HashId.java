package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Objects;
import java.util.Random;

/**
 * This class represents a hash id
 */
public class HashId {
  public static final int SIZE = 64;
  final byte[] hashId;

  public HashId(byte[] id) throws InvalidKeyException {
    if (id.length != SIZE) {
      throw new InvalidKeyException();
    }
    hashId = id.clone();
  }

  public HashId(byte[] id, int offset) throws InvalidKeyException {
    if (id.length + offset < SIZE) {
      throw new InvalidKeyException();
    }
    hashId = new byte[SIZE];
    System.arraycopy(id, offset, hashId, 0, SIZE);
  }

  @Override
  public boolean equals(Object other) {
    if (this == other)
    {
      return true;
    }
    if (other == null)
    {
      return false;
    }
    if (getClass() != other.getClass())
    {
      return false;
    }

    return Arrays.equals(hashId, ((HashId) other).hashId);
  }

  @Override
  public int hashCode()
  {
    int result = 0;
    for (int i = 0; i < hashId.length; i ++) {
      result |= Objects.hashCode(hashId[i]);
    }

    return result;
  }

  public final byte[] raw() {
    return hashId;
  }

  public static HashId random() throws InvalidKeyException, NoSuchAlgorithmException {
    Random r = new SecureRandom();
    byte[] data = new byte[HashId.SIZE];
    r.nextBytes(data);

    MessageDigest md = MessageDigest.getInstance("SHA-512");
    md.update(data);
    return new HashId(md.digest());
  }

  public String toString() {
    char[] hexArray = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[hashId.length * 2];
    for ( int j = 0; j < hashId.length; j++ ) {
      int v = hashId[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }
}