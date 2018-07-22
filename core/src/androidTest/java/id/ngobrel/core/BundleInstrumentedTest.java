package id.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.Iterator;
import java.util.Set;

import id.ngobrel.core.Bundle;
import id.ngobrel.core.BundlePrivate;
import id.ngobrel.core.BundlePublic;
import id.ngobrel.core.PreKeyId;
import id.ngobrel.core.PrivateKey;
import id.ngobrel.core.PublicKey;

@RunWith(AndroidJUnit4.class)
public class BundleInstrumentedTest {
  @Test
  public void testPopulatePreKeys() throws Exception {
    Bundle b = new Bundle();
    b.populatePreKeys();

    byte[] epriv = b.bundlePrivate.encode();
    byte[] epub = b.bundlePublic.encode();

    BundlePrivate dpriv = BundlePrivate.decode(epriv);
    BundlePublic dpub = BundlePublic.decode(epub);

    Set<PreKeyId> eset = b.bundlePrivate.preKeys.keySet();
    Set<PreKeyId> dset = dpriv.preKeys.keySet();

    Assert.assertEquals(eset, dset);
    Iterator<PreKeyId> it = eset.iterator();
    while (it.hasNext()) {
      PreKeyId id = it.next();

      PrivateKey k1 = b.bundlePrivate.preKeys.get(id);
      PrivateKey k2 = dpriv.preKeys.get(id);

      Assert.assertEquals(Arrays.equals(k1.raw(), k2.raw()), true);
    }

    eset = b.bundlePublic.preKeys.keySet();
    dset = dpub.preKeys.keySet();

    Assert.assertEquals(eset, dset);
    it = eset.iterator();
    while (it.hasNext()) {
      PreKeyId id = it.next();

      PublicKey k1 = b.bundlePublic.preKeys.get(id);
      PublicKey k2 = dpub.preKeys.get(id);

      Assert.assertEquals(Arrays.equals(k1.raw(), k2.raw()), true);
    }
  }
}