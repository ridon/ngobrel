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
    len(x.PublicKey.Contents) == 0 ||
    len(x.PrivateKey.Contents) == 0 {
    t.Error("Key was not generated");
  }

  if x.PublicKey.Contents == x.PrivateKey.Contents {
    t.Error("Public key was not computed correctly")
  }

  fmt.Printf("-->%s\n", x.PrivateKey.HexString())
  fmt.Printf("-->%s\n", x.PublicKey.HexString())

  data := []byte("omama")
  sig := x.PrivateKey.Sign(rand.Reader, data)
  if (x.PublicKey.Verify(data, sig) == false) {
    t.Error("Signature can't be verified")
  }
  data[0] &= 0x80;
  if (x.PublicKey.Verify(data, sig) == true) {
    t.Error("Signature can't be verified after altered")
  }
  fmt.Printf("-->%s\n", hex.EncodeToString(sig[:]))

}
