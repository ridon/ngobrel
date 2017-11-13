package crypto

import (
  "crypto/rand"
  "encoding/hex"
  "fmt"
  "github.com/ridon/ngobrel/crypto/Key"
  "testing"
)

func TestRatchetProto(t *testing.T) {
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

  sk, _, err := GetSharedKeySender(random, ephKey, bundleAlice, &bundleBobPublic, "Ridon")
  if err != nil {
    t.Error(err)
  }

  // 6. Alice creates the associated data
  ad := append(bundleAlice.Public.Identity.Encode()[:], bundleBobPublic.Identity.Encode()[:]...)

  aliceRatchet := NewRatchet()
  err = aliceRatchet.InitSelf(random, &bundleBobPublic.Spk.PublicKey, sk)
  if err != nil {
    t.Error(err)
  }

  msgToBeEncrypted := []byte("olala")
  enc, err := aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  // Send enc and aliceRatchet's public data

  bobRatchet := NewRatchet()
  pair := Key.Pair {
    PrivateKey: bundleBob.Private.Spk,
    PublicKey: bundleBob.Public.Spk.PublicKey,
  }
  bobRatchet.InitRemote(&pair, sk)

  dec, err := bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  return
  // ---------------------------------
  // bob replies back

  err = bobRatchet.InitSelf(random, &aliceRatchet.SelfPair.PublicKey, nil)
  if err != nil {
    t.Error(err)
  }

  pairAlice := aliceRatchet.SelfPair
  aliceRatchet.InitRemote(pairAlice, nil)

  msgToBeEncrypted = []byte("olala")
  enc, err = bobRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = aliceRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }


}
