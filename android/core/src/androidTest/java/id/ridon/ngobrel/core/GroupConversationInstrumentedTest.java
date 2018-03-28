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
public class GroupConversationInstrumentedTest {
  final String AliceUserId = "+62-222-849-Alice";
  final String BobUserId = "+62-111-948-Bob";
  final String CharlieUserId = "+62-333-489-Charlie";

  final HashId AliceDeviceId1 = HashId.random();
  final HashId BobDeviceId1 = HashId.random();
  final HashId CharlieDeviceId1 = HashId.random();

  // This is where the server stores the bundle public of the users
  HashMap<String, BundlePublicCollection> serverBundles = new HashMap<>();

  // This is where the server stores the group
  HashMap<HashId, ArrayList<String>> serverGroups = new HashMap<>();

  // Mailboxes
  // Every message is put in an array inside a hashmap of device id and encrypted data
  HashMap<HashId, ArrayList<byte[]>> mailBoxes = new HashMap<>();

  // Group messages are stored here. In real life, the server should put additional effort such as
  // to take note of the received status of each messages for each member of the group.
  HashMap<HashId, ArrayList<byte[]>> groupMessages = new HashMap<>();

  public GroupConversationInstrumentedTest() throws NoSuchAlgorithmException, InvalidKeyException {
  }

  HashId serverRegisterGroup(ArrayList<String> members) throws NoSuchAlgorithmException, InvalidKeyException {
    HashId id = HashId.random();

    serverGroups.put(id, members);
    return id;
  }

  void serverPutToGroup(HashId groupId, byte[] encrypted) {
    ArrayList<byte[]> list = groupMessages.get(groupId);
    if (list == null) {
      list = new ArrayList<>();
    }
    list.add(encrypted);
    groupMessages.put(groupId, list);
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
    mailBoxes.put(id, msgList);
    return data;
  }

  @Test
  public void testEncryptDecrypt() throws Exception {


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

    byte[] encrypted, decrypted;

    // ======================================== ALICE's side of story ===================================================
    // Alice creates a group containing Alice, Bob, and Charlie
    // 1. Alice registers a group in the server
    // This is implementation dependent and not covered here

    ArrayList<String> aliceGroupMembers = new ArrayList<>();
    aliceGroupMembers.add(AliceUserId);
    aliceGroupMembers.add(BobUserId);
    aliceGroupMembers.add(CharlieUserId);
    HashId aliceGroupId = serverRegisterGroup(aliceGroupMembers);

    // 2. Alice must be able to send message to Bob and Charlie,
    //    so she must have a ready conversation with all of the member of the group
    // 2.a.1 She downloads Bob's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceBobBundlePublicCollection = serverBundles.get(BobUserId);
    byte[] download = serverAliceBobBundlePublicCollection.encode();

    // 2.a.2 Alice got Bob's bundle public
    BundlePublicCollection aliceBobBundlePublicCollection = BundlePublicCollection.decode(download);

    // 2.a.3 Alice starts a conversation with Bob
    SesameConversation aliceBobConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), BobUserId, aliceBobBundlePublicCollection);
    aliceBobConversation.initializeSender();

    // 2.b.1 She downloads Charlie's public bundle
    // First, the server prepares it first and make it ready to be downloaded
    BundlePublicCollection serverAliceCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverAliceCharlieBundlePublicCollection.encode();

    // 2.b.2 Alice got Charlie's bundle public
    BundlePublicCollection aliceCharlieBundlePublicCollection = BundlePublicCollection.decode(download);

    // 2.b.3 Alice starts a conversation with Charlie
    SesameConversation aliceCharlieConversation = new SesameConversation(AliceUserId, aliceDevice.id, aliceDevice.getBundle(), CharlieUserId, aliceCharlieBundlePublicCollection);
    aliceCharlieConversation.initializeSender();

    // 3. At this moment, Alice has her own copy of the GroupConversation object
    // 3.1 She creates her sender key
    GroupConversation aliceGroup = new GroupConversation();
    aliceGroup.initSender(AliceDeviceId1);
    MessageExamplePayload aliceSenderKeyPayload = new MessageExamplePayload(aliceGroup.getSenderKey());

    // 3.2 And sends it to all of group participants
    // First to Bob
    encrypted = aliceBobConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And to Charlie
    encrypted = aliceCharlieConversation.encrypt(aliceSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // And alice keeps the sender key for herself, so she can read whatever she sent to the group
    aliceGroup.initRecipient(aliceSenderKeyPayload.contents);

    // That's it for setting up a group conversation.
    // Next she can send her first message to the group
    byte[] message = "Welcome".getBytes();

    encrypted = aliceGroup.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // == BOB's story ===============================================================================================
    // Bob gets an information from server that he's been added to a group which was created by Alice
    // It means:
    // 1. He's expecting senderKey from Alice, which means he's creating a receiver side of SesameConversation
    //    or reuse the conversation if it is already created in past time
    BundlePublicCollection serverBobAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverBobAliceBundlePublicCollection.encode();

    BundlePublicCollection bobAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobAliceConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), AliceUserId, bobAliceBundlePublicCollection);

    MessageExamplePayload payload = null;
    download = serverFetchEncrypted(bobDevice.id);

    decrypted = bobAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    GroupConversation bobAliceGroupConversation = new GroupConversation();
    bobAliceGroupConversation.initRecipient(payload.contents);

    // Bob must know which messages he's not yet got from the server
    int bobAliceGroupIndex = 0;

    byte[] groupEncryptedMessage = serverGetFromGroup(aliceGroupId, bobAliceGroupIndex++);
    decrypted = bobAliceGroupConversation.decrypt(groupEncryptedMessage);

    Assert.assertArrayEquals(decrypted, message);

    // Then Bob wants to reply
    // First he must generate his senderKey
    bobAliceGroupConversation.initSender(BobDeviceId1);

    MessageExamplePayload bobSenderKeyPayload = new MessageExamplePayload(bobAliceGroupConversation.getSenderKey());

    // And he must send it to both Alice and Charlie

    encrypted = bobAliceConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    // He had a conversation with Alice but not with Charlie, so he must initiate conversation with Charlie

    BundlePublicCollection serverBobCharlieBundlePublicCollection = serverBundles.get(CharlieUserId);
    download = serverBobCharlieBundlePublicCollection.encode();

    BundlePublicCollection bobCharlieBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation bobCharlieConversation = new SesameConversation(BobUserId, bobDevice.id, bobDevice.getBundle(), CharlieUserId, bobCharlieBundlePublicCollection);
    bobCharlieConversation.initializeSender();

    encrypted = bobCharlieConversation.encrypt(bobSenderKeyPayload.encode());
    serverPutToMailbox(encrypted);

    message = "Hello from Bob".getBytes();
    encrypted = bobAliceGroupConversation.encrypt(message);
    serverPutToGroup(aliceGroupId, encrypted);

    // Alice reads the message

    while (true) {
      download = serverFetchEncrypted(aliceDevice.id);
      if (download == null) {
        break;
      }

      decrypted = aliceBobConversation.decrypt(download);
      payload = MessageExamplePayload.decode(decrypted);
      // Check whether this is a sender key message
      Assert.assertEquals(payload.type, 2);

      // Before decrypting, alice initialize the sender key from the payload
      aliceGroup.initRecipient(payload.contents);
    }

    int aliceAliceGroupIndex = 0;

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // This is the first message Alice sent to the group
    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, aliceAliceGroupIndex++);
    decrypted = aliceGroup.decrypt(download);

    // And this is the second message, coming from Bob
    Assert.assertArrayEquals(decrypted, message);


    // == Charlie's story ===============================================================================================
    // Charlie gets an information from server that he's been added to a group which was created by Alice
    // It means:
    // 1. He's expecting senderKey from Alice, which means he's creating a receiver side of SesameConversation
    //    or reuse the conversation if it is already created in past time
    BundlePublicCollection serverCharlieAliceBundlePublicCollection = serverBundles.get(AliceUserId);
    download = serverCharlieAliceBundlePublicCollection.encode();
    BundlePublicCollection charlieAliceBundlePublicCollection = BundlePublicCollection.decode(download);

    BundlePublicCollection serverCharlieBobBundlePublicCollection = serverBundles.get(BobUserId);
    download = serverCharlieBobBundlePublicCollection.encode();
    BundlePublicCollection charlieBobBundlePublicCollection = BundlePublicCollection.decode(download);

    SesameConversation charlieAliceConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), AliceUserId, charlieAliceBundlePublicCollection);
    SesameConversation charlieBobConversation = new SesameConversation(CharlieUserId, charlieDevice.id, charlieDevice.getBundle(), BobUserId, charlieBobBundlePublicCollection);

    GroupConversation charlieAliceGroupConversation = new GroupConversation();

    // Get the first private message, came from Alice
    download = serverFetchEncrypted(charlieDevice.id);
    decrypted = charlieAliceConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);

    // This one is from Bob
    // In real life, you should do this differently
    download = serverFetchEncrypted(charlieDevice.id);

    decrypted = charlieBobConversation.decrypt(download);
    payload = MessageExamplePayload.decode(decrypted);
    // Check whether this is a sender key message
    Assert.assertEquals(payload.type, 2);

    charlieAliceGroupConversation.initRecipient(payload.contents);


    int charlieAliceGroupIndex = 0;
    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, "Welcome".getBytes());

    download = serverGetFromGroup(aliceGroupId, charlieAliceGroupIndex++);
    decrypted = charlieAliceGroupConversation.decrypt(download);

    Assert.assertArrayEquals(decrypted, message);


  }

  private byte[] serverGetFromGroup(HashId aliceGroupId, int i) {
    ArrayList<byte[]> group = groupMessages.get(aliceGroupId);
    return group.get(i);
  }

  private HashId serverRegisterGroup() throws NoSuchAlgorithmException, InvalidKeyException {
    HashId id = HashId.random();

    return id;
  }
}