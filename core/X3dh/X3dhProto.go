package X3dh

import (
  "crypto/sha512"
  "errors"
  "github.com/ridon/ngobrel/core/Key"
  "github.com/ridon/ngobrel/core/Kdf"
  "io"
)

// Helper
func clear(a *[32]byte) {
  b := *a
  for i := 0; i < len(*a); i++ {
    b[i] = 0
  }
}

// This should be the same as AEAD key size
const skLen = 32
func GetSharedKeySender(random io.Reader, ephKey *Key.Pair, me *Key.Bundle, you *Key.BundlePublic, info string) ([]byte, *[32]byte, error){
  dh1 := me.Private.Identity.ShareSecret(you.Spk.PublicKey)
  dh2 := ephKey.PrivateKey.ShareSecret(you.Identity)
  dh3 := ephKey.PrivateKey.ShareSecret(you.Spk.PublicKey)

  // Create a shared key
  keys := make([]byte, 0)
  oneTimePreKeyId, oneTimePreKey := you.PopPreKey()
  if oneTimePreKey != nil {
    dh4 := ephKey.PrivateKey.ShareSecret(*oneTimePreKey)
    keys = append(dh1[:], append(dh2[:], append(dh3[:], dh4[:]...)...)...)
    clear(&dh1)
    clear(&dh2)
    clear(&dh3)
    clear(&dh4)
  } else {
    keys = append(dh1[:], append(dh2[:], dh3[:]...)...)
    clear(&dh1)
    clear(&dh2)
    clear(&dh3)
  }

  hashFn := sha512.New
  salt := make([]byte, hashFn().Size())
  sk, err := Kdf.KDF(hashFn, keys, salt, info, skLen)
  if err != nil || (err == nil && len(sk) != skLen) {
    if err != nil {
      return nil, nil, err
    } else {
      return nil, nil, errors.New("KDF error")
    }
  }
  ephKey.PrivateKey.Clear()

  return sk, &oneTimePreKeyId, nil
}

func GetSharedKeyRecipient(message *Message, me *Key.Bundle, you *Key.BundlePublic, info string) ([]byte, error){
  ephKey := message.EphKey
  preKeyId := message.PreKeyId

  dh1 := me.Private.Spk.ShareSecret(you.Identity)
  dh2 := me.Private.Identity.ShareSecret(*ephKey)
  dh3 := me.Private.Spk.ShareSecret(*ephKey)

  // Create a shared key
  keys := make([]byte, 0)
  oneTimePreKeyPrivate := me.Private.FetchPreKey(preKeyId)

  if oneTimePreKeyPrivate != nil {
    dh4 := oneTimePreKeyPrivate.ShareSecret(*ephKey)
    keys = append(dh1[:], append(dh2[:], append(dh3[:], dh4[:]...)...)...)
    clear(&dh1)
    clear(&dh2)
    clear(&dh3)
    clear(&dh4)
  } else {
    keys = append(dh1[:], append(dh2[:], dh3[:]...)...)
    clear(&dh1)
    clear(&dh2)
    clear(&dh3)
  }

  hashFn := sha512.New
  salt := make([]byte, hashFn().Size())
  sk, err := Kdf.KDF(hashFn, keys, salt, info, skLen)
  if err != nil || (err == nil && len(sk) != skLen) {
    if err != nil {
      return nil, err
    } else {
      return nil, errors.New("KDF error")
    }
  }
  if oneTimePreKeyPrivate != nil {
    oneTimePreKeyPrivate.Clear()
  }

  return sk, nil
}
