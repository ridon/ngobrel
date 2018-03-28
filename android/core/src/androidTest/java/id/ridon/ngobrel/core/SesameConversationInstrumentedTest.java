package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class SesameConversationInstrumentedTest {
  final String AliceUserId = "+62-222-849-Alice";
  final String BobUserId = "+62-111-948-Bob";

  final String AliceDeviceId1 = "8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be";
  final String BobDeviceId1 = "092fcfbbcfca3b5be7ae1b5e58538e92c35ab273ae13664fed0d67484c8e78a6";
  final String BobDeviceId2 = "6297f7a86e92f27510b0a06b74ef79a7c52b491825b7d7e8af39ebc17aa7143b";

  // This is where the server stores the bundle public of the users
  HashMap<String, BundlePublicCollection> serverBundles = new HashMap<>();

  // Mailboxes
  // Every message is put in an array inside a hashmap of device id and encrypted data
  HashMap<HashId, ArrayList<byte[]>> mailBoxes = new HashMap<>();

  void serverPutToMailbox(byte[] encrypted) throws IOException, InvalidKeyException {
    HashMap<HashId, byte[]> unpacked = SesameConversation.unpackEncrypted(encrypted);
    Set<HashId> hashIds = unpacked.keySet();
    Iterator<HashId> it = hashIds.iterator();
    while (it.hasNext()) {
      HashId id = it.next();
      ArrayList<byte[]> msgList = mailBoxes.get(id);
      if (msgList == null) {
        msgList = new ArrayList<>();
      }
      byte[] data = unpacked.get(id);
      msgList.add(data);
      mailBoxes.put(id, msgList);
    }
  }

  byte[] serverFetchEncrypted(HashId id) {
    ArrayList<byte[]> msgList = mailBoxes.get(id);
    if (msgList == null) {
      msgList = new ArrayList<>();
    }
    if (msgList.size() == 0) {
      return null;
    }
    byte[] data = msgList.get(0);
    if (data != null) {
      msgList.remove(0);
    }
    return data;
  }

  @Test
  public void testEncryptDecrypt() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    String message = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);
    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob downloads all the messages from bobDevice.id
    while (true) {
      download = serverFetchEncrypted(bobDevice.id);
      if (download == null) {
        break;
      }

      decrypted = bobConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Bob replies back
    message = "bob-msg1-alice-msg1";
    encrypted = bobConversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    // Alice downloads the messages
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Alice replies back
    message = "alice-msg2";
    encrypted = aliceConversation.encrypt(message.getBytes());

    // Bob downloads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }
  }

  @Test
  public void testEncryptDecryptMultipleDevice() throws Exception {

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(new HashId(AliceDeviceId1.getBytes()), AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(new HashId(AliceDeviceId1.getBytes()), BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob has two devices
    SesameSenderDevice bobDevice1 = new SesameSenderDevice(new HashId(BobDeviceId1.getBytes()), BobUserId);
    SesameSenderDevice bobDevice2 = new SesameSenderDevice(new HashId(BobDeviceId2.getBytes()), BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw1 = bobDevice1.getBundle().bundlePublic.encode();
    byte[] bobBundlePublicRaw2 = bobDevice2.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(new HashId(BobDeviceId1.getBytes()), BundlePublic.decode(bobBundlePublicRaw1));
    bobBundlePublicCollection.put(new HashId(BobDeviceId2.getBytes()), BundlePublic.decode(bobBundlePublicRaw2));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Alice wants to send a message to Bob
    // She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBundlePublicCollection.encode();

    // Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // Alice starts a conversation with Bob
    SesameConversation aliceConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceConversation.initializeSender();

    String message = "alice-msg1";

    byte[] decrypted;
    byte[] encrypted = aliceConversation.encrypt(message.getBytes());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    // Server then -- in some way -- tells Bob that he has an incoming message
    // Bob then initiates a conversation on his side
    // He does that by downloading Alice's bundle
    BundlePublicCollection serverBobBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobConversation = new SesameConversation(BobUserId, bobDevice2.id, bobDevice2.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    // Bob downloads all the messages from bobDevice.id
    while (true) {
      download = serverFetchEncrypted(bobDevice2.id);
      if (download == null) {
        break;
      }

      decrypted = bobConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Bob replies back
    message = "bob-msg1-alice-msg1";
    encrypted = bobConversation.encrypt(message.getBytes());

    // And uploads to server
    serverPutToMailbox(encrypted);

    // Alice downloads the messages
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }

    // Alice replies back
    message = "alice-msg2";
    encrypted = aliceConversation.encrypt(message.getBytes());

    // Bob downloads the message
    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceConversation.decrypt(download);
      Assert.assertEquals(Arrays.equals(decrypted, message.getBytes()), true);
    }
  }
}
