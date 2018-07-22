package id.ngobrel.core;

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

public class RatchetMessageHeader {
  public final PublicKey publicKey;
  public final int chainLength;
  public final int messageNumber;
  public static final int SIZE = 4 + 4 + 33;

  public RatchetMessageHeader(final PublicKey publicKey, int chainLength, int messageNumber) {
    this.publicKey = publicKey;
    this.chainLength = chainLength;
    this.messageNumber = messageNumber;
  }

  public byte[] encode() {
    byte[] ret = new byte[SIZE];
    System.arraycopy(publicKey.encode(), 0, ret, 0, 33);
    ByteBuffer b = ByteBuffer.allocate(4);
    b.putInt(chainLength);
    System.arraycopy(b.array(), 0, ret, 33, 4);
    b.clear();
    b.putInt(messageNumber);
    System.arraycopy(b.array(), 0, ret, 33 + 4, 4);
    return ret;
  }

  public static RatchetMessageHeader decode(byte[] raw) throws InvalidKeyException, IllegalDataSizeException {
    if (raw.length != (SIZE)) {
      throw new IllegalDataSizeException();
    }

    PublicKey k = PublicKey.decode(raw, 0);
    ByteBuffer b = ByteBuffer.wrap(raw, 33, 4);
    int chainLength = b.getInt();
    b = ByteBuffer.wrap(raw, 33 + 4, 4);
    int messageNumber = b.getInt();

    RatchetMessageHeader h = new RatchetMessageHeader(k, chainLength, messageNumber);
    return h;
  }


}
