package X3dh 

import (
  "errors"
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

func (m *Message) EncodeMessage() []byte{
  ret := make([]byte, 0)
  ret = append(ret[:], m.Identity.Encode()...)
  ret = append(ret[:], m.EphKey.Encode()...)
  ret = append(ret[:], m.PreKeyId[:]...)
  ret = append(ret[:], m.Message[:]...)
  return ret
}

func DecodeMessage(msg []byte) (*Message, error){
  if len(msg) < 99 {
    return nil, errors.New("Message length invalid")
  }

  identity, err := Key.DecodePublic(msg[:33], 0)
  if err != nil {
    return nil, err
  }

  ephKey, err := Key.DecodePublic(msg[33:66], 0)
  if err != nil {
    return nil, err
  }

  var preKey [32]byte
  copy(preKey[:], msg[66:98])
  message := msg[98:]

  m := Message {
    Identity: identity,
    EphKey: ephKey,
    PreKeyId: preKey,
    Message: message,
  }

  return &m, nil
}

