package Sesame
import (
  "fmt"

  "bytes"
  "github.com/ridon/ngobrel/crypto/Key"
  "testing"
  "time"
)

const AliceUserId = "+62-222-849-Alice"
const BobUserId = "+62-111-948-Bob"

type message struct {
  id [64]byte
  time time.Time
  data []byte
  sender string
  senderDeviceId HashId
}

type deviceData struct {
  id HashId
  messages []message
  bundle Key.BundlePublic
}

type devices map[HashId] deviceData

type user struct {
  userId string
  devices []deviceData
}

type users map[string] user
type mailboxes map[string] []message

type server struct {
  devices devices
  users users
  mailbox mailboxes
}

func newServer() server {
  s := server {
    devices: make(map[HashId] deviceData),
    users: make(map[string] user),
    mailbox: make(map[string] []message),
  }
  return s
}

func (s *server) downloadMessages(user string) []message {
  mbox, _ := s.mailbox[user]
  return mbox
}

func (s *server) uploadMessage(sender string, senderDeviceId HashId, to string, data []byte) {
  mbox, ok := s.mailbox[to]
  if ok == false {
    mbox = make([]message, 0)
  }

  msg := message {
    data: data,
    sender: sender,
    senderDeviceId: senderDeviceId,
  }
  mbox = append(mbox[:], msg)
  s.mailbox[to] = mbox
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
  record, ok := s.devices[id]
  if ok == false {
    record = deviceData {
      id: id,
    }
  }
  record.bundle = *bundle

  s.devices[id] = record

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

  // Bob downloads Alice's bundle
  bobAliceBundle := server.downloadBundle(AliceUserId)

  aliceSession := NewSession(aliceSelfDevice.Bundle, BobUserId, aliceBobBundle)
  aliceSession.InitSender()
  aliceMessage := []byte("alice-msg1")
  aliceMessageEnc, err := aliceSession.Encrypt(bobDeviceId, aliceMessage)
  if err != nil {
    t.Error(err)
  }
  server.uploadMessage(AliceUserId, aliceDeviceId, BobUserId, aliceMessageEnc)

  bobSession := NewSession(bobSelfDevice.Bundle, AliceUserId, bobAliceBundle)
  bobMessageEncs := server.downloadMessages(BobUserId)
  for _, v := range bobMessageEncs {
    bobMessageDec, err := bobSession.Decrypt(aliceDeviceId, v.data)
    if err != nil {
      t.Error(err)
    }
    if !bytes.Equal(bobMessageDec, aliceMessage) {
      t.Error("Decrypt failed")
    }
  }

  fmt.Println("")

}
