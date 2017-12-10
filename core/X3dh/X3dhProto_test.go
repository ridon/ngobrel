package X3dh

import (
  "bytes"
  "crypto/rand"
  "fmt"
  "github.com/ridon/ngobrel/core/Key"
  "testing"
)

/**
 This tests X3DH protocol where Bob sends a message to Alice
*/
func TestX3dhProto(t *testing.T) {
  random := rand.Reader

  // 1. Bob uploads his public key bundles
  bundleBob, _ := Key.NewBundle(random)
  bundleBob.PopulatePreKeys(random, 100)

  bundleBobPublic := bundleBob.Public // Alice only can access bob's public keys 

  // 2. Alice verifies the SPK
  bundleAlice, _ := Key.NewBundle(random)
  res := bundleBobPublic.Verify();


  if res == false {
    t.Error("SPK is not verified")
  }

  // 3. Alice creates an ephemeral key
  ephKey, err := Key.Generate(random)
  if err != nil {
   t.Error("Ephemeral key is not created") 
  }

  // 4. Alice creates a shared key
  // 5. Alice clears the ephemeral key and keys' content

  sk, preKeyId, err := GetSharedKeySender(random, ephKey, bundleAlice, &bundleBobPublic, "Ridon") 
  if err != nil {
    t.Error(err)
  }

  // 6. Alice creates the associated data
  ad := append(bundleAlice.Public.Identity.Encode()[:], bundleBobPublic.Identity.Encode()[:]...)

  // 7. Alice creates the first message

  msgToBeEncrypted := []byte("olala")
  message, err := NewMessage(&bundleAlice.Public.Identity, &ephKey.PublicKey, *preKeyId, sk, msgToBeEncrypted, ad)

  if err != nil {
    t.Error(err)
  }

  // message is then transfered to transit place

  // 1. Bob fetches Alice keys and all private keys

  bundleAlicePublic := bundleAlice.Public

  // 2. Bob gets the shared key
  skBob, err := GetSharedKeyRecipient(message, bundleBob, &bundleAlicePublic, "Ridon")

  if err != nil {
    t.Error(err)
  }

  if !bytes.Equal(sk, skBob) {
    t.Error("SK is different")
  }

  // 3. Bob creates the associated data
  adBob := append(bundleAlicePublic.Identity.Encode()[:], bundleBobPublic.Identity.Encode()[:]...)

  if !bytes.Equal(ad, adBob) {
    t.Error("SK is different")
  }

  // 4. Bob decrypts the message
  decrypted, err := message.DecryptMessage(skBob, adBob)
  if err != nil {
    t.Error(err)
  }

  if len(decrypted) == 0 {
    t.Error("Decrypted data is zero length")
  }

  if !bytes.Equal(decrypted, msgToBeEncrypted) {
    t.Error("Can't decrypt")
  }

  fmt.Printf("")
}

func TestEncodeDecodeMessage(t *testing.T) {
  var i [32]byte
  var e [32]byte
  var k [32]byte
  copy(i[:], []byte("e983f374794de9c64e3d1c1de1d490c075"))
  copy(e[:], []byte("8fe2c645ad50e087da0296f1e7e22c0871"))
  copy(k[:], []byte("2f7c71de750a2c43fd12f92ae298dba522"))

  m := Message {
    Identity: Key.NewPublic(i),
    EphKey: Key.NewPublic(e),
    PreKeyId: k,
    Message: []byte("omama"),
  }

  me := m.EncodeMessage()

  if len(me) != 32 + 1 + 32 + 1 + 32 + 5 {
    t.Error("Encoding failed")
  }

  ms, err := DecodeMessage(me)
  if err != nil {
    t.Error(err)
  }

  if !ms.Identity.PublicKeyEquals(m.Identity) {
    t.Error("Identity can't be decoded")
  }

  if !ms.EphKey.PublicKeyEquals(m.EphKey) {
    t.Error("Eph key can't be decoded")
  }
  if !bytes.Equal(ms.PreKeyId[:], m.PreKeyId[:]) {
    t.Error("PreKey can't be decoded")
  }
  fmt.Println(ms.Message, m.Message)
  if !bytes.Equal(ms.Message, m.Message) {
    t.Error("Message can't be decoded")
  }

}
