package Ratchet

import (
  "crypto/rand"
  "github.com/ridon/ngobrel/core/Key"
  "testing"
)

func TestHeader(t *testing.T) {
  random := rand.Reader

  pair, _ := Key.Generate(random)
  h := Header {
    PublicKey: &pair.PublicKey,
    ChainLength: 123,
    MessageNumber: 456,
  }
  s := h.SerializeHeader()

  s0 := make([]byte, 39)
  _, err := DeserializeHeader(s0)
  if err == nil {
    t.Error("Should be failed")
    t.Error(err)
  }

  d, err := DeserializeHeader(s)
  if err != nil {
    t.Error(err)
  }
  if h.PublicKey != d.PublicKey &&
      h.ChainLength != d.ChainLength &&
      h.MessageNumber != d.MessageNumber {
    t.Error("Header can't be deserialized")
  }
}
