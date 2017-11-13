package crypto

import (
  "github.com/ridon/ngobrel/crypto/aead"
  "github.com/ridon/ngobrel/crypto/Key"
)
type Message struct {
  Identity *Key.Public
  EphKey *Key.Public
  PreKeyId [32]byte
  Message []byte
}

const infoCipher = "RidonX3DMessage"
func NewMessage(identity *Key.Public, ephKey *Key.Public, id [32]byte, key []byte, message []byte, ad []byte) (*Message, error) {

  e, err := aead.Encrypt(key, message, ad, infoCipher)
  if err != nil {
    return nil, err
  }

  m := Message{
    Identity: identity,
    EphKey: ephKey,
    PreKeyId: id,
    Message: e,
  }
  return &m, nil
}

func (msg *Message) DecryptMessage(key []byte, ad []byte) ([]byte, error) {
  e, err := aead.Decrypt(key, msg.Message, ad, infoCipher)
  if err != nil {
    return nil, err
  }

  return e, nil
}
