package x3dh

import (
  "crypto/rand"
  "crypto/sha512"
  "encoding/hex"
  "fmt"
  "github.com/ridon/ngobrel/crypto/xeddsa"
  "testing"
)

func TestKdf(t *testing.T) {
  secret := []byte("Omama")
  info := "Olala"
  kdf, _ := KDF(sha512.New, secret, info, 32)
  if (kdf == nil) {
    t.Error("KDF didn't give output")
  }
  if (len(kdf) != 32) {
    t.Error("KDF didn't give correct output size")
  }

  fmt.Printf("%v", kdf);
}

func TestSharedSecret(t *testing.T) {
  aliceKey,_ := xeddsa.Generate(rand.Reader)
  bobKey,_ := xeddsa.Generate(rand.Reader)

  aliceShared := GenerateSharedSecret(bobKey.PublicKey.Contents, aliceKey.PrivateKey.Contents)
  bobShared := GenerateSharedSecret(aliceKey.PublicKey.Contents, bobKey.PrivateKey.Contents)

  if (aliceShared != bobShared) {
    t.Error("Shared secrets not computed correctly")
  }

  info := "Ridon"
  aliceDerived, _ := KDF(sha512.New, aliceShared[:32], info, 64)
  bobDerived, _ := KDF(sha512.New, bobShared[:32], info, 64)

  if hex.EncodeToString(aliceDerived) != hex.EncodeToString(bobDerived) {
    t.Error("Shared secrets not computed correctly")
  }
}
