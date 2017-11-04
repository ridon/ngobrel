package crypto

import (
  "github.com/ridon/ngobrel/crypto/Key"
  "golang.org/x/crypto/chacha20poly1305"
)
type Message struct {
  Identity *Key.Public
  EphKey *Key.Public
  PreKeyId [32]byte
  Nonce []byte
  Message []byte
}

func NewMessage(identity *Key.Public, ephKey *Key.Public, id [32]byte, nonce []byte, key []byte, message []byte, ad []byte) (*Message, error) {

  enc, err := chacha20poly1305.New(key)
  if err != nil {
    return nil, err
  }

  var encrypted []byte
  e := enc.Seal(encrypted, nonce, message, ad)

  m := Message{
    Identity: identity,
    EphKey: ephKey,
    PreKeyId: id,
    Nonce: nonce,
    Message: e,
  }
  return &m, nil
}

func (msg *Message) DecryptMessage(key []byte, ad []byte) (*[]byte, error) {

  enc, err := chacha20poly1305.New(key)
  if err != nil {
    return nil, err
  }

  decrypted := make([]byte, 0)
  d, err := enc.Open(decrypted, msg.Nonce, msg.Message, ad)
  if err != nil {
    return nil, err
  }

  return &d, nil
}
