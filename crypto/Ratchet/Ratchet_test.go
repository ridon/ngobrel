package Ratchet

import (
  "crypto/rand"
  "encoding/hex"
  "fmt"
  "github.com/ridon/ngobrel/crypto/Key"
  "github.com/ridon/ngobrel/crypto/X3dh"
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

  sk, _, err := X3dh.GetSharedKeySender(random, ephKey, bundleAlice, &bundleBobPublic, "Ridon")
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

  bobRatchet := NewRatchet()
  pair := Key.Pair {
    PrivateKey: bundleBob.Private.Spk,
    PublicKey: bundleBob.Public.Spk.PublicKey,
  }
  bobRatchet.InitRemote(&pair, sk)

  msgToBeEncrypted := []byte("olala")
  enc, err := aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  // Send enc and aliceRatchet's public data

  dec, err := bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  // ---------------------------------
  // bob replies back

  msgToBeEncrypted = []byte("olala2")
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

  // ---------------------------------
  // bob writes again 

  msgToBeEncrypted = []byte("olala2")
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

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  // ---------------------------------
  // bob writes again but not delivered 

  msgToBeEncryptedLate1 := []byte("olala2")
  encLate1, err := bobRatchet.Encrypt(msgToBeEncryptedLate1, ad)
  if err != nil {
    t.Error(err)
  }

  // ---------------------------------
  // bob writes again 

  msgToBeEncrypted = []byte("olala2")
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

  // ---------------------------------
  // bob writes again 

  msgToBeEncrypted = []byte("olala2")
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
  // ---------------------------------
  // bob writes again but not delivered 

  msgToBeEncryptedLate2 := []byte("olala2")
  encLate2, err := bobRatchet.Encrypt(msgToBeEncryptedLate2, ad)
  if err != nil {
    t.Error(err)
  }

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  // ---------------------------------
  // alice writes again but not delivered 

  msgToBeEncryptedLateAlice1 := []byte("olala alice1")
  encLateAlice1, err := aliceRatchet.Encrypt(msgToBeEncryptedLateAlice1, ad)
  if err != nil {
    t.Error(err)
  }

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")


  // ---------------------------------
  // message encLate2 arrived later 

  dec, err = aliceRatchet.Decrypt(encLate2, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncryptedLate2) {
    t.Error("Unable to decrypt")
  }

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")



  // ---------------------------------
  // message encLate1 arrived later 

  dec, err = aliceRatchet.Decrypt(encLate1, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncryptedLate1) {
    t.Error("Unable to decrypt")
  }

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  // --------------------------------
  // alice replies
  msgToBeEncrypted = []byte("olala")
  enc, err = aliceRatchet.Encrypt(msgToBeEncrypted, ad)
  if err != nil {
    t.Error(err)
  }

  dec, err = bobRatchet.Decrypt(enc, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncrypted) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")

  // --------------------------------
  // Bob received AliceLate1
  dec, err = bobRatchet.Decrypt(encLateAlice1, ad)
  if err != nil {
    t.Error(err)
  }

  if hex.EncodeToString(dec) != hex.EncodeToString(msgToBeEncryptedLateAlice1) {
    t.Error("Unable to decrypt")
  }
  fmt.Printf("")



}
