package crypto

import (
  "crypto/hmac"
  "crypto/sha512"
  "github.com/ridon/ngobrel/crypto/aead"
  "github.com/ridon/ngobrel/crypto/Key"
  "github.com/ridon/ngobrel/crypto/x3dh"
  "io"
)

const Info string = "Ridon"
const InfoCipher string = "Ridon"
type KeyId [32]byte
type MessageMap map[KeyId] int

type Ratchet struct {
  SelfPair *Key.Pair
  RemotePublic *Key.Public
  RootKey []byte
  ChainKeySelf []byte
  ChainKeyRemote []byte
  NextHeaderKey []byte
  HeaderKey []byte
  MessageNumberSelf int
  MessageNumberRemote int
  PreviousNumbers int
  SkippedMessages MessageMap
}

func NewRatchet() *Ratchet {
  r := Ratchet{
  }
  return &r
}

func (r *Ratchet) InitSelf(random io.Reader, remotePubKey *Key.Public, sk []byte) error {
  pair, err := Key.Generate(random)
  if err != nil {
    return err
  }

  dh := pair.PrivateKey.ShareSecret(*remotePubKey)
  kdf, err := x3dh.KDF(sha512.New, dh[:], sk, Info, 64)
  if err != nil {
    return err
  }

  r.SelfPair = pair
  r.RemotePublic = remotePubKey
  r.RootKey = kdf[:32]
  r.ChainKeySelf = kdf[32:]
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.PreviousNumbers = 0

  return nil
}

func (r *Ratchet) InitRemote(remotePair *Key.Pair, sk []byte) {

  r.SelfPair = remotePair
  r.RootKey = sk
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.PreviousNumbers = 0
}

func (r *Ratchet) encrypt(data []byte, ad []byte) (*[]byte, error) {
  m := make([]byte, 1)
  m[0] = 1
  mac := hmac.New(sha512.New, r.ChainKeySelf)
  mac.Write(m)
  sum := mac.Sum(nil)

  r.ChainKeySelf = sum[:32]
  mk := sum[32:]

  e, err := aead.Encrypt(mk, data, ad, InfoCipher)
  if err != nil {
    return nil, err
  }

  r.MessageNumberSelf += 1
  return e, nil
}

func (r *Ratchet) decrypt(data []byte, ad []byte) (*[]byte, error) {
  m := make([]byte, 1)
  m[0] = 1
  mac := hmac.New(sha512.New, r.ChainKeyRemote)
  mac.Write(m)
  sum := mac.Sum(nil)

  r.ChainKeyRemote = sum[:32]
  mk := sum[32:]

  e, err := aead.Decrypt(mk, data, ad, InfoCipher)
  if err != nil {
    return nil, err
  }

  r.MessageNumberRemote += 1
  return e, nil
}

func (r *Ratchet) turn(random io.Reader, remotePubKey *Key.Public) error {
  r.PreviousNumbers = r.MessageNumberSelf
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.RemotePublic = remotePubKey

  dh := r.SelfPair.PrivateKey.ShareSecret(*remotePubKey)
  kdf, err := x3dh.KDF(sha512.New, dh[:], r.RootKey, Info, 64)

  pair, err := Key.Generate(random)
  if err != nil {
    return err
  }
  r.RootKey = kdf[:32]
  r.ChainKeyRemote = kdf[32:]
  r.SelfPair = pair

  dh = r.SelfPair.PrivateKey.ShareSecret(*r.RemotePublic)
  kdf, err = x3dh.KDF(sha512.New, dh[:], r.RootKey, Info, 64)

  pair, err = Key.Generate(random)
  if err != nil {
    return err
  }
  r.RootKey = kdf[:32]
  r.ChainKeySelf = kdf[32:]

  return nil
}


