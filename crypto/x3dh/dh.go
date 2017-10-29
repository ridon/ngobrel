package x3dh

import (
  "golang.org/x/crypto/curve25519"
)

func GenerateSharedSecret(key1, key2[32]byte) [32]byte {
  var sharedSecret [32]byte
  curve25519.ScalarMult(&sharedSecret, &key2, &key1)

	return sharedSecret
}
