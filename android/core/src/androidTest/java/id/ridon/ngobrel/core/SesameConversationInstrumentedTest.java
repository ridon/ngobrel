package id.ridon.ngobrel.core;

import android.support.test.runner.AndroidJUnit4;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

@RunWith(AndroidJUnit4.class)
public class SesameConversationInstrumentedTest {
  final String AliceUserId = "+62-222-849-Alice";
  final String BobUserId = "+62-111-948-Bob";
  final String CharlieUserId = "+62-333-008-Charlie";

  final HashId AliceDeviceId1 = HashId.random();
  final HashId BobDeviceId1 = HashId.random();
  final HashId BobDeviceId2 = HashId.random();
  final HashId CharlieDeviceId1 = HashId.random();

  // This is where the server stores the bundle public of the users
  HashMap<String, BundlePublicCollection> serverBundles = new HashMap<>();

  // Mailboxes
  // Every message is put in an array inside a hashmap of device id and encrypted data
  HashMap<HashId, ArrayList<byte[]>> mailBoxes = new HashMap<>();

  // Media
  HashMap<HashId, byte[]> mediaFiles = new HashMap<>();

  public SesameConversationInstrumentedTest() throws NoSuchAlgorithmException, InvalidKeyException {
  }


  // This simulates uploading a file to a URL
  // Returning an ID string
  String serverUploadMedia(byte[] media) throws NoSuchAlgorithmException, InvalidKeyException {
    HashId id = HashId.random();
    mediaFiles.put(id, media);

    return id.toString();
  }

  // This simulates downloading a file from a URL
  byte[] serverDownloadMedia(String url) throws InvalidKeyException {
    return mediaFiles.get(new HashId(Utils.fromHexString(url)));
  }

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
    mailBoxes = new HashMap<>();

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(AliceDeviceId1, AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(AliceDeviceId1, BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(BobDeviceId1, BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(BobDeviceId1, BundlePublic.decode(bobBundlePublicRaw));
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
    mailBoxes = new HashMap<>();

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(AliceDeviceId1, AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(AliceDeviceId1, BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob has two devices
    SesameSenderDevice bobDevice1 = new SesameSenderDevice(BobDeviceId1, BobUserId);
    SesameSenderDevice bobDevice2 = new SesameSenderDevice(BobDeviceId2, BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw1 = bobDevice1.getBundle().bundlePublic.encode();
    byte[] bobBundlePublicRaw2 = bobDevice2.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(BobDeviceId1, BundlePublic.decode(bobBundlePublicRaw1));
    bobBundlePublicCollection.put(BobDeviceId2, BundlePublic.decode(bobBundlePublicRaw2));
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

  @Test
  public void testEncryptDecryptMultipleRecipients() throws Exception {
    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(AliceDeviceId1, AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(AliceDeviceId1, BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(BobDeviceId1, BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(BobDeviceId1, BundlePublic.decode(bobBundlePublicRaw));
    serverBundles.put(BobUserId, bobBundlePublicCollection);

    // Also does Charlie
    SesameSenderDevice charlieDevice = new SesameSenderDevice(CharlieDeviceId1, CharlieUserId);

    // and uploads his
    byte[] charlieBundlePublicRaw = charlieDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection charlieBundlePublicCollection = new BundlePublicCollection(CharlieDeviceId1, BundlePublic.decode(charlieBundlePublicRaw));
    serverBundles.put(CharlieUserId, charlieBundlePublicCollection);

    byte[] encrypted, decrypted, download;

    BundlePublicCollection serverAliceBobBundlePublicCollection = serverBundles.get(BobUserId);
    download = serverAliceBobBundlePublicCollection.encode();
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation aliceBobConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceBobConversation.initializeSender();

    BundlePublicCollection serverAliceCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverAliceCharlieBundlePublicCollection.encode();
    BundlePublicCollection aliceCharlieBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation aliceCharlieConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), CharlieUserId, aliceCharlieBundlePublicCollection);
    aliceCharlieConversation.initializeSender();

    encrypted = aliceBobConversation.encrypt("Hello bob".getBytes());
    serverPutToMailbox(encrypted);

    // And to Charlie
    encrypted = aliceCharlieConversation.encrypt("Hello charlie".getBytes());
    serverPutToMailbox(encrypted);

    encrypted = aliceCharlieConversation.encrypt("Hello again charlie".getBytes());
    serverPutToMailbox(encrypted);

    BundlePublicCollection serverBobAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobAliceBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobAliceConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    Assert.assertArrayEquals("Hello bob".getBytes(), decrypted);

    encrypted = bobAliceConversation.encrypt("Hello alice".getBytes());
    serverPutToMailbox(encrypted);

    BundlePublicCollection serverBobCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverBobCharlieBundlePublicCollection.encode();
    BundlePublicCollection bobCharlieBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobCharlieConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), CharlieUserId, bobCharlieBundlePublicCollection);
    bobCharlieConversation.initializeSender();

    // and send it to server
    encrypted = bobCharlieConversation.encrypt("Hello charlie from bob".getBytes());
    serverPutToMailbox(encrypted);

    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      Assert.assertArrayEquals("Hello alice".getBytes(), decrypted);
    }

    BundlePublicCollection serverCharlieBobBundlePublicCollection = serverBundles.get(BobUserId);
    download = serverCharlieBobBundlePublicCollection.encode();
    BundlePublicCollection charlieBobBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation charlieBobConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), BobUserId, charlieBobBundlePublicCollection);

    BundlePublicCollection serverCharlieAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverCharlieAliceBundlePublicCollection.encode();
    BundlePublicCollection charlieAliceBundlePublicCollection = BundlePublicCollection.decode(download);
    SesameConversation charlieAliceConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), AliceUserId, charlieAliceBundlePublicCollection);

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    Assert.assertArrayEquals("Hello charlie".getBytes(), decrypted);

    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    Assert.assertArrayEquals("Hello again charlie".getBytes(), decrypted);

    // This one is from Bob
    download = serverFetchEncrypted(charlieDevice.id);
    System.err.println("D: Bob to Charlie");
    decrypted = charlieBobConversation.decrypt(download);
    Assert.assertArrayEquals("Hello charlie from bob".getBytes(), decrypted);
  }

  @Test
  public void testMedia() throws Exception {
    mailBoxes = new HashMap<>();

    // Alice got a device
    SesameSenderDevice aliceDevice = new SesameSenderDevice(AliceDeviceId1, AliceUserId);

    // Alice uploads her bundle
    byte[] aliceBundlePublicRaw = aliceDevice.getBundle().bundlePublic.encode();

    // She sents the AliceDeviceId1 and the above raw data
    // Server keeps it
    // according to the device and user
    BundlePublicCollection aliceBundlePublicCollection = new BundlePublicCollection(AliceDeviceId1, BundlePublic.decode(aliceBundlePublicRaw));
    serverBundles.put(AliceUserId, aliceBundlePublicCollection);

    // Bob also has a device
    SesameSenderDevice bobDevice = new SesameSenderDevice(BobDeviceId1, BobUserId);

    // and uploads his
    byte[] bobBundlePublicRaw = bobDevice.getBundle().bundlePublic.encode();

    // Server then gets it
    // and collect it by it's device id
    BundlePublicCollection bobBundlePublicCollection = new BundlePublicCollection(BobDeviceId1, BundlePublic.decode(bobBundlePublicRaw));
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
    byte[] encrypted = aliceConversation.encrypt(new MessageExamplePayload(null, message.getBytes()).encode());

    // The encrypted text is uploaded to server. Server then puts it in a mailbox
    serverPutToMailbox(encrypted);

    // Alice sends out a media file
    // This is the meta data we prepare
    String ad = "MEDIA";
    String contentType = "image/png";
    String fileName = "image.png";
    byte[] image = "PNG.This is an image.blbbblblablabla".getBytes();
    byte[] key = HashId.random().raw();

    // Then we encrypt the media file
    Aead mediaEncryptor = new Aead(key, "My Chat App");
    encrypted = mediaEncryptor.encrypt(image, ad.getBytes());

    // And upload
    String urlFromServer = serverUploadMedia(encrypted);

    // And send a media payload
    encrypted = aliceConversation.encrypt(new MessageExamplePayload(null, urlFromServer, contentType, fileName, key).encode());

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

    download = serverFetchEncrypted(bobDevice.id);
    Assert.assertNotNull(download);
    decrypted = bobConversation.decrypt(download);
    MessageExamplePayload payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 0); // This is a plain message
    Assert.assertEquals(Arrays.equals(payload.contents, message.getBytes()), true);

    download = serverFetchEncrypted(bobDevice.id);
    Assert.assertNotNull(download);
    decrypted = bobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    Assert.assertEquals(payload.type, 1); // This is a media message

    // Lets decrypt the message first by getting it from the URL it specified
    String urlFromPayload = payload.url;
    byte[] mediaFromServer = serverDownloadMedia(urlFromPayload);

    // We got the media, now decrypt it using the key from the payload
    Aead aeadBob = new Aead(payload.contents, "My Chat App");
    decrypted = aeadBob.decrypt(mediaFromServer, ad.getBytes()); // ad and info must be exactly the same

    // Check whether the decrypted is really the same with the image Alice sent in the first place
    Assert.assertEquals(Arrays.equals(decrypted, image), true);

  }


}
