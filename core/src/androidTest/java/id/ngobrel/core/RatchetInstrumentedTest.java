package id.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Random;
import java.util.Set;

import id.ngobrel.core.Bundle;
import id.ngobrel.core.BundlePublic;
import id.ngobrel.core.Key;
import id.ngobrel.core.KeyPair;
import id.ngobrel.core.PublicKey;
import id.ngobrel.core.Ratchet;
import id.ngobrel.core.RatchetMessageBuffer;
import id.ngobrel.core.SharedKey;
import id.ngobrel.core.X3dhMessage;

@RunWith(AndroidJUnit4.class)
public class RatchetInstrumentedTest {
  @Test
  public void testProto() throws Exception {
    // Bob has a bundle
    Bundle bundleBob = new Bundle();
    bundleBob.populatePreKeys();

    // Bob uploads the bundle
    byte[] uploadBundlePublicBob = bundleBob.bundlePublic.encode();

    // Alice also has a bundle
    Bundle bundleAlice = new Bundle();

    // And uploads her as well
    byte[] uploadBundlePublicAlice = bundleAlice.bundlePublic.encode();

    // Alice downloads Bob's public key
    BundlePublic bundlePublicBob = BundlePublic.decode(uploadBundlePublicBob);

    // Alice creates an ephemeral key
    KeyPair ephAlice = new KeyPair();

    // And use it to create a shared secret together with Bob's public key
    SharedKey skAliceBob = X3dhMessage.getSharedKeySender(ephAlice, bundleAlice.bundlePrivate, bundlePublicBob, "Ridon");

    // Alice creates an AD
    byte[] adAlice = new byte[33 + 33];
    System.arraycopy(bundleAlice.bundlePublic.identity.encode(), 0, adAlice, 0, 33);
    System.arraycopy(bundlePublicBob.identity.encode(), 0, adAlice, 33, 33);

    // Alice creates a ratchet
    Ratchet ratchetAliceBob = new Ratchet();
    ratchetAliceBob.initSender(bundlePublicBob.spk.publicKey, new Key(skAliceBob.key));

    // Alice encrypts a first message and upload it
    String msg = "Olala";
    byte[] uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Somehow, Bob knows that he got a message from Alice
    byte[] downloadEnc = uploadEnc.clone();

    // Bob downloads Alice's public and creates an AD
    BundlePublic bundlePublicAlice = BundlePublic.decode(uploadBundlePublicAlice);

    // Bob computes a shared key
    //byte[] skBob = msgBob.getSharedKeyRecipient(msgBob.ephKey, msgBob.preKeyId, bundleBob.bundlePrivate, bundlePublicAlice,"RidonTest");

    byte[] skBob = skAliceBob.key;

    // And he creates an AD
    byte[] adBob = new byte[33 + 33];
    System.arraycopy(bundlePublicAlice.identity.encode(), 0, adBob, 0, 33);
    System.arraycopy(bundleBob.bundlePublic.identity.encode(), 0, adBob, 33, 33);

    // Bob creates a ratchet
    Ratchet ratchetBobAlice = new Ratchet();
    KeyPair pair = new KeyPair(bundleBob.bundlePrivate.spk, bundleBob.bundlePublic.spk.publicKey);

    ratchetBobAlice.initRecipient(pair, new Key(skBob));

    byte[] dec = ratchetBobAlice.decrypt(downloadEnc, adBob);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Bob replies back
    msg = "Omama";
    uploadEnc = ratchetBobAlice.encrypt(msg.getBytes(), adBob);

    // Alice downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Bob writes again
    msg = "Osama";
    uploadEnc = ratchetBobAlice.encrypt(msg.getBytes(), adBob);

    // Alice downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Alice replies
    msg = "Obama";
    uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Bob downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Bob writes again but not delivered
    String msgLate1 = "Osama is late";
    byte[] uploadEncLate1 = ratchetBobAlice.encrypt(msgLate1.getBytes(), adBob);

    // Bob writes again
    msg = "Okama";
    uploadEnc = ratchetBobAlice.encrypt(msg.getBytes(), adBob);

    // Alice downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Bob writes again
    msg = "Orama";
    uploadEnc = ratchetBobAlice.encrypt(msg.getBytes(), adBob);

    // Alice downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Bob writes again but not delivered
    String msgLate2 = "Osama is late again";
    byte[] uploadEncLate2 = ratchetBobAlice.encrypt(msgLate2.getBytes(), adBob);

    // Alice replies
    msg = "Obama";
    uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Bob downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adBob);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // Alice writes again but not delivered
    String msgLate3 = "Orama is late again";
    byte[] uploadEncLate3 = ratchetAliceBob.encrypt(msgLate3.getBytes(), adAlice);

    // Alice writes again
    msg = "Owama ";
    uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Bob downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adBob);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // one of the message to Alice arrived and she downloads the message
    downloadEnc = uploadEncLate2.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msgLate2.getBytes(), dec), true);

    // Alice replies
    msg = "Obama has arrived";
    uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Bob downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adBob);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // The last message to Alice arrived and she downloads the message
    downloadEnc = uploadEncLate1.clone();

    // And decrypts it
    dec = ratchetAliceBob.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msgLate1.getBytes(), dec), true);

    // Alice replies again
    msg = "Obama has arrived yet?";
    uploadEnc = ratchetAliceBob.encrypt(msg.getBytes(), adAlice);

    // Bob downloads the message
    downloadEnc = uploadEnc.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adAlice);

    Assert.assertEquals(Arrays.equals(msg.getBytes(), dec), true);

    // The message to Bob arrived and he downloads the message
    downloadEnc = uploadEncLate3.clone();

    // And decrypts it
    dec = ratchetBobAlice.decrypt(downloadEnc, adBob);

    Assert.assertEquals(Arrays.equals(msgLate3.getBytes(), dec), true);


    // FIN.
  }

  @Test
  public void testEncodeDecode() throws Exception {
    KeyPair pairSender = new KeyPair();
    PublicKey publicRecipient = pairSender.publicKey;
    Key rootKey = new Key(pairSender.privateKey.shareSecret(pairSender.publicKey));
    Key chainKeySender = new Key(
        pairSender.privateKey.shareSecret(new PublicKey(rootKey.raw()))
    );
    Key chainKeyRecipient = new Key(
        pairSender.privateKey.shareSecret(
            new PublicKey(chainKeySender.raw()))
    );
    Key nextHeader = new Key(
        pairSender.privateKey.shareSecret(
            new PublicKey(chainKeyRecipient.raw()))
    );
    Key header = new Key(
        pairSender.privateKey.shareSecret(
            new PublicKey(nextHeader.raw()))
    );
    int messageNumberSender = 12;
    int messageNumberRecipient = 34;
    int chainLength = 56;
    HashMap<Key, RatchetMessageBuffer> skippedMessages = new HashMap<>();

    int size = 13;
    for (int i = 0; i < size; i++) {
      Random r = new Random();
      byte[] b = new byte[32];
      r.nextBytes(b);
      RatchetMessageBuffer buffer = new RatchetMessageBuffer(i, new Key(b));
      r.nextBytes(b);
      Key k = new Key(b);
      skippedMessages.put(k, buffer);
    }

    Ratchet r1 = new Ratchet();
    r1.build(pairSender, publicRecipient, rootKey,
        chainKeySender, chainKeyRecipient, nextHeader, header,
        messageNumberSender, messageNumberRecipient, chainLength,
        skippedMessages);

    byte[] e = r1.encode();

    Ratchet r2 = Ratchet.decode(e);

    Assert.assertEquals(r1.pairSender, r2.pairSender);
    Assert.assertEquals(r1.publicRecipient, r2.publicRecipient);
    Assert.assertEquals(r1.rootKey, r2.rootKey);
    Assert.assertEquals(r1.chainKeySender, r2.chainKeySender);
    Assert.assertEquals(r1.chainKeyRecipient, r2.chainKeyRecipient);
    Assert.assertEquals(r1.nextHeader, r2.nextHeader);
    Assert.assertEquals(r1.header, r2.header);
    Assert.assertEquals(r1.messageNumberRecipient, r2.messageNumberRecipient);
    Assert.assertEquals(r1.messageNumberSender, r2.messageNumberSender);
    Assert.assertEquals(r1.chainLength, r2.chainLength);
    Assert.assertEquals(r1.skippedMessages.size(), r2.skippedMessages.size());

    Set<Key> keyIds = r1.skippedMessages.keySet();
    Iterator<Key> it = keyIds.iterator();
    while (it.hasNext()) {
      Key id = it.next();
      RatchetMessageBuffer buf1 = r1.skippedMessages.get(id);
      RatchetMessageBuffer buf2 = r2.skippedMessages.get(id);

      Assert.assertEquals(buf1, buf2);

    }
  }
}