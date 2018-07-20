package id.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import id.ngobrel.core.Bundle;
import id.ngobrel.core.BundlePublic;
import id.ngobrel.core.KeyPair;
import id.ngobrel.core.SharedKey;
import id.ngobrel.core.X3dhMessage;

@RunWith(AndroidJUnit4.class)
public class X3dhMessageInstrumentedTest {
  @Test
  public void proto() throws Exception {

    // Bob creates his bundle
    Bundle bundleBob = new Bundle();
    bundleBob.populatePreKeys();

    // Bob uploads his bundle
    BundlePublic bundlePublicBob = bundleBob.bundlePublic;

    // Alice creates her bundle
    Bundle bundleAlice = new Bundle();

    // Alice verifies Bob's bundle
    Assert.assertEquals(bundlePublicBob.verify(), true);

    // Alice creates an ephemeral key
    KeyPair ephAlice = new KeyPair();

    // and creates a shared key
    SharedKey skAlice = X3dhMessage.getSharedKeySender(ephAlice, bundleAlice.bundlePrivate, bundlePublicBob, "RidonTest");

    // Alice creates an AD for herself
    byte[] aliceAliceIdentity = bundleAlice.bundlePublic.identity.encode();
    byte[] aliceBobIdentity = bundlePublicBob.identity.encode();

    byte[] adAlice = new byte[aliceAliceIdentity.length + aliceBobIdentity.length];
    System.arraycopy(aliceAliceIdentity, 0, adAlice, 0, 0);
    System.arraycopy(aliceBobIdentity, 0, adAlice, 0, aliceAliceIdentity.length);

    // Alice creates the first message
    byte[] messageString = "Olala".getBytes(StandardCharsets.UTF_8);
    X3dhMessage message = new X3dhMessage(bundleAlice.bundlePublic.identity,
                                            ephAlice.publicKey,
                                            skAlice.preKeyId,
                                            skAlice.key,
                                            messageString,
                                            adAlice);

    // The message is encoded
    byte[] msgUpload = message.encode();

    // The message is then uploaded to transit
    // and downloaded by Bob
    byte[] msgDownload = msgUpload.clone();
    X3dhMessage msgBob = X3dhMessage.decode(msgDownload);

    // Bob retrieves Alice's public bundle
    BundlePublic bundlePublicAlice = bundleAlice.bundlePublic;

    // Bob computes a shared key
    byte[] skBob = msgBob.getSharedKeyRecipient(msgBob.ephKey, msgBob.preKeyId, bundleBob.bundlePrivate, bundlePublicAlice,"RidonTest");

    // Check point
    Assert.assertEquals(Arrays.equals(skAlice.key, skBob), true);

    // Bob computes ad
    byte[] bobAliceIdentity = bundlePublicAlice.identity.encode();
    byte[] bobBobIdentity = bundleBob.bundlePublic.identity.encode();
    byte[] adBob = new byte[bobAliceIdentity.length + bobAliceIdentity.length];
    System.arraycopy(bobAliceIdentity, 0, adBob, 0, 0);
    System.arraycopy(bobBobIdentity, 0, adBob, 0, bobAliceIdentity.length);

    // Check point
    Assert.assertEquals(Arrays.equals(adAlice, adBob), true);

    // Bob decrypts the message
    byte[] decrypted = msgBob.decrypt(skBob, adBob);

    // Check point
    Assert.assertEquals(Arrays.equals(decrypted, messageString), true);

  }

}