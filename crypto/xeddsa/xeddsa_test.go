package xeddsa

import (
  "encoding/hex"
  "fmt"
  "testing"
  "crypto/rand"
)

func TestGenerate(t *testing.T) {
  var x, _ = Generate(rand.Reader)

  if x == nil ||
    len(x.publicKey.key) == 0 ||
    len(x.privateKey.key) == 0 {
    t.Error("Key was not generated");
  }

  if x.publicKey.key == x.privateKey.key {
    t.Error("Public key was not computed correctly")
  }

  fmt.Printf("-->%s\n", x.privateKey.HexString())
  fmt.Printf("-->%s\n", x.publicKey.HexString())

  data := []byte("omama")
  sig := x.privateKey.Sign(rand.Reader, data)
  if (x.publicKey.Verify(data, sig) == false) {
    t.Error("Signature can't be verified")
  }
  data[0] &= 0x80;
  if (x.publicKey.Verify(data, sig) == true) {
    t.Error("Signature can't be verified after altered")
  }
  fmt.Printf("-->%s\n", hex.EncodeToString(sig[:]))

}
