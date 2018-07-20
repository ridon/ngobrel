package id.ngobrel.core;
import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import id.ngobrel.core.Constants;
import id.ngobrel.core.Kdf;

@RunWith(AndroidJUnit4.class)
public class KdfInstrumentedTest {
  @Test
  public void testKdf() throws Exception {
    byte[] salt = Constants.getRidonSalt512();
    byte[] keys = "Olala".getBytes();
    Kdf kdf = Kdf.KdfSha512(keys, salt);
    byte[] kdfResult = kdf.get("Omama", 32);

    Assert.assertEquals(kdfResult.length, 32);
  }

}