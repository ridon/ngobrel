package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class RatchetMessageHeaderInstrumentedTest {
  @Test
  public void testEncodeDecode() throws Exception {
    KeyPair x = new KeyPair();

    RatchetMessageHeader m1 = new RatchetMessageHeader(x.publicKey, 12, 34);
    byte[] m1Encoded = m1.encode();

    RatchetMessageHeader m2 = RatchetMessageHeader.decode(m1Encoded);
    Assert.assertEquals(m1.publicKey, m2.publicKey);
    Assert.assertEquals(m1.chainLength, m2.chainLength);
    Assert.assertEquals(m1.messageNumber, m2.messageNumber);
  }

}