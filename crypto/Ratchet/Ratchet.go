package Ratchet

import (
  "crypto/hmac"
  "crypto/rand"
  "crypto/sha512"
  "encoding/binary"
  "errors"
  "github.com/ridon/ngobrel/crypto/aead"
  "github.com/ridon/ngobrel/crypto/Kdf"
  "github.com/ridon/ngobrel/crypto/Key"
  "io"
)

const maxSkip int = 1024*1024
const Info string = "Ridon"
const InfoCipher string = "Ridon"
type KeyId [32]byte
type MessageBuffers struct {
  Number int
  Key []byte
}
type MessageMap map[KeyId] MessageBuffers

type Header struct {
  PublicKey *Key.Public
  ChainLength int
  MessageNumber int
}

func (h *Header) SerializeHeader() []byte {
  cl := make([]byte, 8)
  binary.PutUvarint(cl, uint64(h.ChainLength))
  num := make([]byte, 8)
  binary.PutUvarint(num, uint64(h.MessageNumber))
  return append(h.PublicKey[:], append(cl, num...)...)
}

func DeserializeHeader(b []byte) (*Header, error) {
  if len(b) != 48 {
    return nil, errors.New("Invalid header's length")
  }

  var pk0 [32]byte
  copy(pk0[:], b[:32])
  pk := Key.NewPublic(pk0)

  cl := binary.LittleEndian.Uint64(b[32:40])
  num := binary.LittleEndian.Uint64(b[40:48])

  h := Header {
    PublicKey: pk,
    ChainLength: int(cl),
    MessageNumber: int(num),
  }
  return &h, nil

}

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
  ChainLength int
  SkippedMessages MessageMap
}

func NewRatchet() *Ratchet {
  r := Ratchet{
    SkippedMessages: make(map[KeyId] MessageBuffers),
  }
  return &r
}

func (r *Ratchet) InitSelf(random io.Reader, remotePubKey *Key.Public, rk []byte) error {
  pair, err := Key.Generate(random)
  if err != nil {
    return err
  }

  dh := pair.PrivateKey.ShareSecret(*remotePubKey)
  var rootKey = rk
  if rk == nil {
    rootKey = r.RootKey
  }
  kdf, err := Kdf.KDF(sha512.New, dh[:], rootKey, Info, 64)
  if err != nil {
    return err
  }

  r.SelfPair = pair
  r.RemotePublic = remotePubKey
  r.RootKey = kdf[:32]
  r.ChainKeySelf = kdf[32:]
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.ChainLength = 0

  return nil
}

func (r *Ratchet) InitRemote(remotePair *Key.Pair, rk []byte) {

  r.SelfPair = remotePair
  if rk != nil {
    r.RootKey = rk
  }
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.ChainLength = 0
}

func (r *Ratchet) Encrypt(data []byte, ad []byte) ([]byte, error) {
  m := make([]byte, 1)
  m[0] = 1
  mac := hmac.New(sha512.New, r.ChainKeySelf)
  mac.Write(m)
  sum := mac.Sum(nil)

  r.ChainKeySelf = sum[:32]
  mk := sum[32:]

  header := Header {
    PublicKey: &r.SelfPair.PublicKey,
    ChainLength: r.ChainLength,
    MessageNumber: r.MessageNumberSelf,
  }
  hs := header.SerializeHeader()

  e, err := aead.Encrypt(mk, data, append(ad, hs...), InfoCipher)
  if err != nil {
    return nil, err
  }

  r.MessageNumberSelf += 1

  ret := append(hs[:], e...)
  return ret, nil
}

func (r *Ratchet) trySkippedMessages(h *Header, data []byte, ad []byte, hs []byte) ([]byte, error) {
  mk := r.SkippedMessages.FindSkippedKey(h.PublicKey, h.MessageNumber)
  if mk == nil {
    return nil, nil
  }
  e, err := aead.Decrypt(mk, data, append(ad, hs...), InfoCipher)
  if err != nil {
    return nil, err
  }
  return e, nil
}

func (r *Ratchet) Decrypt(data []byte, ad []byte) ([]byte, error) {
  hs := data[:48]
  h, err := DeserializeHeader(hs)
  if err != nil {
    return nil, err
  }

  e, err := r.trySkippedMessages(h, data[48:], ad, hs)
  if err != nil {
    return nil, err
  }
  if e != nil {
    return e, nil
  }

  if !h.PublicKey.PublicKeyEquals(r.RemotePublic) {
    r.skipMessages(h.ChainLength)
    r.turn(rand.Reader, h.PublicKey)
  }
  r.skipMessages(h.MessageNumber)

  m := make([]byte, 1)
  m[0] = 1
  mac := hmac.New(sha512.New, r.ChainKeyRemote)
  mac.Write(m)
  sum := mac.Sum(nil)

  r.ChainKeyRemote = sum[:32]
  mk := sum[32:]

  e, err = aead.Decrypt(mk, data[48:], append(ad, hs...), InfoCipher)
  if err != nil {
    return nil, err
  }

  r.MessageNumberRemote += 1
  return e, nil
}

func (r *Ratchet) turn(random io.Reader, remotePubKey *Key.Public) error {
  r.ChainLength = r.MessageNumberSelf
  r.MessageNumberSelf = 0
  r.MessageNumberRemote = 0
  r.RemotePublic = remotePubKey

  dh := r.SelfPair.PrivateKey.ShareSecret(*remotePubKey)
  kdf, err := Kdf.KDF(sha512.New, dh[:], r.RootKey, Info, 64)

  pair, err := Key.Generate(random)
  if err != nil {
    return err
  }
  r.RootKey = kdf[:32]
  r.ChainKeyRemote = kdf[32:]
  r.SelfPair = pair

  dh = r.SelfPair.PrivateKey.ShareSecret(*r.RemotePublic)
  kdf, err = Kdf.KDF(sha512.New, dh[:], r.RootKey, Info, 64)

  pair, err = Key.Generate(random)
  if err != nil {
    return err
  }
  r.RootKey = kdf[:32]
  r.ChainKeySelf = kdf[32:]

  return nil
}

func (s MessageMap) FindSkippedKey(key *Key.Public, num int) []byte {
  data, ok := s[key.RawPublic()]
  if !ok {
    return nil
  }

  if data.Number != num {
    return nil
  }

  delete(s, key.RawPublic())
  return data.Key
}

func (r *Ratchet) skipMessages(num int) error {
  if r.MessageNumberRemote + maxSkip < num {
    return errors.New("Too many skipped messages")
  }

  if r.ChainKeyRemote != nil {
    for {
      if (r.MessageNumberRemote >= num) {
        break
      }
      m := make([]byte, 1)
      m[0] = 1
      mac := hmac.New(sha512.New, r.ChainKeyRemote)
      mac.Write(m)
      sum := mac.Sum(nil)
      r.ChainKeyRemote = sum[:32]
      mk := sum[32:]
      msg := MessageBuffers {
        Number: r.MessageNumberRemote,
        Key: mk,
      }
      r.SkippedMessages[r.RemotePublic.RawPublic()] = msg
      r.MessageNumberRemote += 1
    }
  }
  return nil
}
