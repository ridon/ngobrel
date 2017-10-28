package x3dh

import (
  "crypto/sha512"
  "fmt"
  "testing"
)

func TestKdf(t *testing.T) {
  secret := []byte("Omama")
  info := "Olala"
  kdf := KDF(sha512.New, secret, info) 
  if (kdf == nil) {
    t.Error("KDF didn't give output")
  }
if (len(kdf) != 32) {
    t.Error("KDF didn't give correct output size")
  }

  fmt.Printf("%v", kdf);
}
