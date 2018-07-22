package id.ngobrel.core;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class RatchetMessageBuffer {
  public final int number;
  public final Key key;

  public RatchetMessageBuffer(int number, Key key) {
    this.number = number;
    this.key = key;
  }

  public byte[] encode() {
    byte[] ret = new byte[4 + 33];
    ByteBuffer b = ByteBuffer.allocate(4);
    b.putInt(number);
    System.arraycopy(b.array(), 0, ret, 0, 4);
    System.arraycopy(key.encode(), 0, ret, 4, 33);
    return ret;
  }

  public static RatchetMessageBuffer decode(final byte[] raw) throws InvalidKeyException, IllegalDataSizeException {
    ByteBuffer b = ByteBuffer.wrap(raw, 0, 4);
    int number = b.getInt();
    return new RatchetMessageBuffer(number, Key.decode(raw, 4));
  }

  @Override
  public boolean equals(Object other) {
    return ((RatchetMessageBuffer) other).number == number &&
        ((RatchetMessageBuffer) other).key.equals(key);
  }
}



