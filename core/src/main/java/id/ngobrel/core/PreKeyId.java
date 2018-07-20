package id.ngobrel.core;

import java.security.InvalidKeyException;
import java.util.Arrays;
import java.util.Objects;

/**
 * This class represents a prekey id
 */

public class PreKeyId {
  final byte[] preKeyId;

  public PreKeyId(byte[] id) throws InvalidKeyException {
    if (id.length != 32) {
      throw new InvalidKeyException();
    }
    preKeyId = id.clone();
  }

  public PreKeyId(byte[] id, int offset) throws InvalidKeyException {
    if (id.length + offset < 32) {
      throw new InvalidKeyException();
    }
    preKeyId = new byte[32];
    System.arraycopy(id, offset, preKeyId, 0, 32);
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

    return Arrays.equals(preKeyId, ((PreKeyId) other).preKeyId);
  }

  @Override
  public int hashCode()
  {
    int result = 0;
    for (int i = 0; i < preKeyId.length; i ++) {
      result |= Objects.hashCode(preKeyId[i]);
    }

    return result;
  }

  public final byte[] raw() {
    return preKeyId;
  }
}
