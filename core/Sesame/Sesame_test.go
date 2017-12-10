package Sesame
import (
  "fmt"

  "bytes"
  "github.com/ridon/ngobrel/core/Key"
  "testing"
)

const AliceUserId = "+62-222-849-Alice"
const BobUserId = "+62-111-948-Bob"

type deviceData struct {
  id HashId
  bundle Key.BundlePublic
}

type devices map[HashId] deviceData

type user struct {
  userId string
  devices []deviceData
}

type users map[string] user
type mailboxes map[HashId] []Message

type server struct {
  users users
  mailbox mailboxes
}

func newServer() server {
  s := server {
    users: make(map[string] user),
    mailbox: make(map[HashId] []Message),
  }
  return s
}

func (s *server) downloadMessages(id HashId) []Message {
  mbox := s.mailbox[id]
  delete(s.mailbox, id)
  return mbox
}

func (s *server) uploadMessage(sender string, senderDeviceId HashId, to string, data MessageBundle) {
  for id, v := range data {
    mbox, ok := s.mailbox[id]
    if ok == false {
      mbox = make([]Message, 0)
    }

    msg := Message {
      Data: v,
      Sender: sender,
    }
    mbox = append(mbox[:], msg)
    s.mailbox[id] = mbox
  }
}

func (s *server) downloadBundle(userId string) map[HashId] Key.BundlePublic {
  u, ok := s.users[userId]
  if ok == false {
    return nil
  }

  bundle := make(map[HashId] Key.BundlePublic)
  for _, v := range u.devices {
    bundle[v.id] = v.bundle
  }

  return bundle
}

func (s *server) uploadBundle(userId string, id HashId, bundle *Key.BundlePublic) bool {
  record := deviceData {
    id: id,
    bundle: *bundle,
  }

  userRecord, ok := s.users[userId]
  if ok == false {
    d := make([]deviceData, 0)
    userRecord = user {
      userId: userId,
      devices: d,
    }
  }
  userRecord.devices = append(userRecord.devices, record)
  s.users[userId] = userRecord

  return true
}

func TestDeviceState(t *testing.T) {
  server := newServer();

  // Alice has an app
  var aliceDeviceId HashId
  copy(aliceDeviceId[:], []byte("8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be"))
  aliceSelfDevice, err := NewSelfDevice(aliceDeviceId, AliceUserId)
  if err != nil {
    t.Error(err)
  }
  // Alice uploads her bundle
  server.uploadBundle(AliceUserId, aliceDeviceId, &aliceSelfDevice.Bundle.Public)

  testAliceUser, ok := server.users[AliceUserId]
  if ok == false {
    t.Error ("Registration failed")
  }

  if testAliceUser.userId != AliceUserId {
    t.Error ("Alice user name is not correctly stored")
  }

  if len(testAliceUser.devices) != 1 {
    t.Error ("Registration of device failed")
  }

  if testAliceUser.devices[0].id != aliceDeviceId {
    t.Error ("Registration of device failed #2")
  }
  
  // Bob also got one
  var bobDeviceId HashId
  copy(bobDeviceId[:], []byte("092fcfbbcfca3b5be7ae1b5e58538e92c35ab273ae13664fed0d67484c8e78a6"))
  bobSelfDevice, err := NewSelfDevice(bobDeviceId, BobUserId)
  if err != nil {
    t.Error(err)
  }
  // Bob uploads his as well
  server.uploadBundle(BobUserId, bobDeviceId, &bobSelfDevice.Bundle.Public)

  testBobUser, ok := server.users[BobUserId]
  if ok == false {
    t.Error ("Registration failed")
  }

  if testBobUser.userId != BobUserId {
    t.Error ("Bob user name is not correctly stored")
  }

  if len(testBobUser.devices) != 1 {
    t.Error ("Registration of device failed")
  }

  if testBobUser.devices[0].id != bobDeviceId {
    t.Error ("Registration of device failed #2")
  }

  // Alice downloads Bob's bundle
  aliceBobBundle := server.downloadBundle(BobUserId)

  // Alice loads or creates a new contact list
  // Bob does that as well
  aliceContacts := make(Contacts)
  bobContacts := make(Contacts)

  // Alice starts to talk to Bob
  aliceConversation := NewConversation(AliceUserId, aliceDeviceId, &aliceContacts, aliceSelfDevice.Bundle, BobUserId, aliceBobBundle)
  aliceConversation.InitSender()
  aliceMessage := []byte("alice-msg1")

  // Alice encrypts her message
  aliceMessageEnc, err := aliceConversation.Encrypt(aliceMessage)
  if err != nil {
    t.Error(err)
  }

  if aliceMessageEnc == nil {
    t.Error("Message is not available")
  }
  // Alice upload her message
  server.uploadMessage(AliceUserId, aliceDeviceId, BobUserId, *aliceMessageEnc)

  // Bob starts a conversation upon receiving a notification
  // about an incoming message from Alice
  // Also, Bob downloads Alice's bundle
  bobAliceBundle := server.downloadBundle(AliceUserId)
  bobConversation := NewConversation(BobUserId, bobDeviceId, &bobContacts, bobSelfDevice.Bundle, AliceUserId, bobAliceBundle)

  // Bob downloads the messages from his one particular device
  bobMessageEncs := server.downloadMessages(bobDeviceId)
  for _, v := range bobMessageEncs {
    // Then it decrypts the message
    bobMessageDec, err := bobConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(bobMessageDec, aliceMessage) {
      t.Error("Decrypt failed")
    }
  }

  bobMessage := []byte("bob-msg1-alice-msg1")
  // Bob replies back
  bobMessageEnc, err := bobConversation.Encrypt(bobMessage)
  if err != nil {
    t.Error(err)
  }
  if bobMessageEnc == nil {
    t.Error("Message is not available")
  }

  // Bob uploads the message
  server.uploadMessage(BobUserId, bobDeviceId, AliceUserId, *bobMessageEnc)
  // and some notification may happen on Alice's side
  // then Alice downloads new messages
  aliceMessageEncs := server.downloadMessages(aliceDeviceId)
  for _, v := range aliceMessageEncs {
    // And decrypts them
    aliceMessageDec, err := aliceConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(aliceMessageDec, bobMessage) {
      t.Error("Decrypt failed")
    }
  }

  // And Alice replies back again
  // This needs to be tested to check whether the session is correctly established
  aliceMessage = []byte("alice-msg2")

  if len(aliceContacts[BobUserId].ActiveSession) == 0 {
    t.Error("Active session is not properly recorded")
  }
  // Alice encrypts her message
  aliceMessageEnc, err = aliceConversation.Encrypt(aliceMessage)
  if err != nil {
    t.Error(err)
  }

  if aliceMessageEnc == nil {
    t.Error("Message is not available")
  }
  // Alice upload her message
  server.uploadMessage(AliceUserId, aliceDeviceId, BobUserId, *aliceMessageEnc)

  // Bob downloads the messages from his one particular device
  bobMessageEncs = server.downloadMessages(bobDeviceId)
  for _, v := range bobMessageEncs {
    // Then it decrypts the message
    bobMessageDec, err := bobConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(bobMessageDec, aliceMessage) {
      t.Error("Decrypt failed")
    }
  }

  // Done 
  fmt.Println("")
}

func TestDeviceStateMultipleDevice1(t *testing.T) {
  server := newServer();

  // Alice has an app
  var aliceDeviceId HashId
  copy(aliceDeviceId[:], []byte("8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be"))
  aliceSelfDevice, err := NewSelfDevice(aliceDeviceId, AliceUserId)
  if err != nil {
    t.Error(err)
  }
  // Alice uploads her bundle
  server.uploadBundle(AliceUserId, aliceDeviceId, &aliceSelfDevice.Bundle.Public)

  testAliceUser, ok := server.users[AliceUserId]
  if ok == false {
    t.Error ("Registration failed")
  }

  if testAliceUser.userId != AliceUserId {
    t.Error ("Alice user name is not correctly stored")
  }

  if len(testAliceUser.devices) != 1 {
    t.Error ("Registration of device failed")
  }

  if testAliceUser.devices[0].id != aliceDeviceId {
    t.Error ("Registration of device failed #2")
  }
  
  // Bob got two devices 
  var bobDeviceId HashId
  var bobDeviceId2 HashId
  copy(bobDeviceId[:], []byte("082fcfbbcfca3b5be7ae1b5e58538e92c35ab273ae13664fed0d67484c8e78a6"))
  bobSelfDevice, err := NewSelfDevice(bobDeviceId, BobUserId)
  if err != nil {
    t.Error(err)
  }
  copy(bobDeviceId2[:], []byte("91938fbbc5ba365ee7af1b2e58438752c3562283a43362bffd0469487c3e8632"))
  bobSelfDevice2, err := NewSelfDevice(bobDeviceId2, BobUserId)
  if err != nil {
    t.Error(err)
  }

  // Bob uploads his as well
  server.uploadBundle(BobUserId, bobDeviceId, &bobSelfDevice.Bundle.Public)
  server.uploadBundle(BobUserId, bobDeviceId2, &bobSelfDevice2.Bundle.Public)

  testBobUser, ok := server.users[BobUserId]
  if ok == false {
    t.Error ("Registration failed")
  }

  if testBobUser.userId != BobUserId {
    t.Error ("Bob user name is not correctly stored")
  }

  if len(testBobUser.devices) != 2 {
    t.Error ("Registration of device failed")
  }

  if testBobUser.devices[0].id != bobDeviceId {
    t.Error ("Registration of device failed #2")
  }

  // Alice downloads Bob's bundle
  aliceBobBundle := server.downloadBundle(BobUserId)

  // Alice loads or creates a new contact list
  // Bob does that as well
  aliceContacts := make(Contacts)
  bobContacts := make(Contacts)

  // Alice starts to talk to Bob
  aliceConversation := NewConversation(AliceUserId, aliceDeviceId, &aliceContacts, aliceSelfDevice.Bundle, BobUserId, aliceBobBundle)
  aliceConversation.InitSender()
  aliceMessage := []byte("alice-msg1")

  // Alice encrypts her message
  aliceMessageEnc, err := aliceConversation.Encrypt(aliceMessage)
  if err != nil {
    t.Error(err)
  }

  if aliceMessageEnc == nil {
    t.Error("Message is not available")
  }
  // Alice upload her message
  server.uploadMessage(AliceUserId, aliceDeviceId, BobUserId, *aliceMessageEnc)

  // Bob starts a conversation upon receiving a notification
  // about an incoming message from Alice in one of his device
  // Also, Bob downloads Alice's bundle
  bobAliceBundle := server.downloadBundle(AliceUserId)
  bobConversation := NewConversation(BobUserId, bobDeviceId2, &bobContacts, bobSelfDevice2.Bundle, AliceUserId, bobAliceBundle)

  // Bob downloads the messages from his one particular device
  bobMessageEncs := server.downloadMessages(bobDeviceId2)
  count := 0
  for _, v := range bobMessageEncs {
    count ++
    // Then it decrypts the message
    bobMessageDec, err := bobConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(bobMessageDec, aliceMessage) {
      t.Error("Decrypt failed")
    }
  }
  if count == 0 {
    t.Error("No messages was found")
  }

  bobMessage := []byte("bob-msg1-alice-msg1")
  // Bob replies back
  bobMessageEnc, err := bobConversation.Encrypt(bobMessage)
  if err != nil {
    t.Error(err)
  }
  if bobMessageEnc == nil {
    t.Error("Message is not available")
  }

  // Bob uploads the message
  server.uploadMessage(BobUserId, bobDeviceId2, AliceUserId, *bobMessageEnc)
  // and some notification may happen on Alice's side
  // then Alice downloads new messages
  aliceMessageEncs := server.downloadMessages(aliceDeviceId)
  for _, v := range aliceMessageEncs {
    // And decrypts them
    aliceMessageDec, err := aliceConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(aliceMessageDec, bobMessage) {
      t.Error("Decrypt failed")
    }
  }

  if len(aliceContacts[BobUserId].ActiveSession) == 0 {
    t.Error("Active session is not properly recorded")
  }
  // And Alice replies back again
  // This needs to be tested to check whether the session is correctly established
  aliceMessage = []byte("alice-msg2")

  // Alice encrypts her message
  aliceMessageEnc, err = aliceConversation.Encrypt(aliceMessage)
  if err != nil {
    t.Error(err)
  }

  if aliceMessageEnc == nil {
    t.Error("Message is not available")
  }
  // Alice upload her message
  server.uploadMessage(AliceUserId, aliceDeviceId, BobUserId, *aliceMessageEnc)

  // Bob downloads the messages from his one particular device
  bobMessageEncs = server.downloadMessages(bobDeviceId2)
  for _, v := range bobMessageEncs {
    // Then it decrypts the message
    bobMessageDec, err := bobConversation.Decrypt(v)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(bobMessageDec, aliceMessage) {
      t.Error("Decrypt failed")
    }
  }

  // Done 
  fmt.Println("")

}
