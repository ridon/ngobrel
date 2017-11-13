package crypto
import (
  "bytes"
  "crypto/rand"
  "fmt"
  "github.com/ridon/ngobrel/crypto/Key"
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
