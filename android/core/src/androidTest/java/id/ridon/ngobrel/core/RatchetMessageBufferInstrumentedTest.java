package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RatchetMessageBufferInstrumentedTest {
  @Test
  public void testEncodeDecode() throws Exception {
    KeyPair p = new KeyPair();

    RatchetMessageBuffer b1 = new RatchetMessageBuffer(9, new Key(p.publicKey.raw()));
    byte[] enc1 = b1.encode();

    RatchetMessageBuffer b2 = RatchetMessageBuffer.decode(enc1);

    Assert.assertEquals(b1.number, b2.number);
    Assert.assertEquals(b1.key, b2.key);
  }

}