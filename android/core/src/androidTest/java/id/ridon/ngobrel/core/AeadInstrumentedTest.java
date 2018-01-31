package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import java.util.Arrays;
import java.util.Random;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(AndroidJUnit4.class)
public class AeadInstrumentedTest {

  @Test
  public void testEncryptDecrypt() throws Exception {
    String ad = "Omama";
    String data = "Olala";
    String info = "Info";
    Random r = new Random();

    byte[] key = new byte[Key.SIZE];
    r.nextBytes(key);

    Aead enc = new Aead(key, info);
    byte[] encrypted = enc.encrypt(data.getBytes(), ad.getBytes());

    Aead dec = new Aead(key, info);
    byte[] decrypted = dec.decrypt(encrypted, ad.getBytes());

    Assert.assertEquals(Arrays.equals(data.getBytes(), decrypted), true);
  }

}