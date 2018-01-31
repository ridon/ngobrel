package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class represents a hash id
 */
public class HashId {
  public static final int SIZE = 64;
  final byte[] hashId;

  HashId(byte[] id) throws InvalidKeyException {
    if (id.length != SIZE) {
      throw new InvalidKeyException();
    }
    hashId = id.clone();
  }

  HashId(byte[] id, int offset) throws InvalidKeyException {
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
}