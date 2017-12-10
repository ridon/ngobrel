package aead

import (
  "bytes"
  "fmt"
  "testing"
)

func TestEncryptDecrypt(t *testing.T) {
  ad := []byte("Omama")
  data := []byte("Olala")
  var key [32]byte
  info := "Info"

  enc, err := Encrypt(key[:], data, ad, info)
  if err != nil {
    t.Error(err)
  }
  dec, err := Decrypt(key[:], enc, ad, info)
  if err != nil {
    t.Error(err)
  }

  if !bytes.Equal(data, dec) {
    t.Error("Can't decrypt")
  }

  fmt.Println("")
}
