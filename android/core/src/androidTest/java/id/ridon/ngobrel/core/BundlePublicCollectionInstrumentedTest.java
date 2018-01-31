package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import static org.junit.Assert.*;

import java.security.SecureRandom;
import java.util.Iterator;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class BundlePublicCollectionInstrumentedTest {
  @Test
  public void testEncodeDecode() throws Exception {
    int max = 41;

    BundlePublicCollection b1 = new BundlePublicCollection();
    for (int i = 0; i < max; i ++) {

      SecureRandom r = new SecureRandom();
      byte[] h = new byte[HashId.SIZE];
      r.nextBytes(h);
      HashId id = new HashId(h);
      Bundle b = new Bundle();

      b1.put(id, b.bundlePublic);
    }

    byte[] bEnc = b1.encode();

    BundlePublicCollection b2 = BundlePublicCollection.decode(bEnc);
    Set<HashId> ids = b1.getIds();
    Iterator<HashId> it = ids.iterator();
    while (it.hasNext()) {
      HashId hashId = it.next();
      BundlePublic bp0 = b1.get(hashId);
      BundlePublic bp1 = b2.get(hashId);

      Assert.assertEquals(bp0.equals(bp1), true);
    }
  }

}