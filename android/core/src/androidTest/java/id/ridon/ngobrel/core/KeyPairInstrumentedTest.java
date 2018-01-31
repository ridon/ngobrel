package id.ridon.ngobrel.core;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;


@RunWith(AndroidJUnit4.class)
public class KeyPairInstrumentedTest {
  @Test
  public void testT() throws Exception {
    KeyPair p = new KeyPair();

    String omama = "Omama";
    Signature sig = p.privateKey.sign(omama.getBytes(StandardCharsets.UTF_8));

    Assert.assertEquals(p.publicKey.verify(omama.getBytes(StandardCharsets.UTF_8), sig),true);
  }

  @Test
  public void testShareSecret() throws Exception {
    KeyPair p = new KeyPair();
    KeyPair q = new KeyPair();

    byte[] sp = p.privateKey.shareSecret(q.publicKey);
    byte[] sq = q.privateKey.shareSecret(p.publicKey);

    Assert.assertEquals(Arrays.equals(sp, sq), true);

  }

  @Test
  public void testEncodeDecode() throws Exception {
    KeyPair p1 = new KeyPair();

    byte[] e = p1.encode();
    KeyPair p2 = KeyPair.decode(e);

    Assert.assertEquals(p1, p2);
  }
}