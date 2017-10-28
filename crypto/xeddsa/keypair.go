package xeddsa

import (
  "golang.org/x/crypto/curve25519"
  "io"
)
const bitsize = 256
const keysize = bitsize/8

type KeyPair struct {
  publicKey PublicKey
  privateKey PrivateKey
}

func Generate(random io.Reader) (*KeyPair, error) {
  var priv, pub [keysize]byte

  _, err := io.ReadFull(random, priv[:])
	if err != nil {
		return nil, err
	}
  priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
  curve25519.ScalarBaseMult(&pub, &priv)

  privateKey := NewPrivateKey(priv)
  publicKey := NewPublicKey(pub)
  pair := KeyPair {
    publicKey: *publicKey,
    privateKey: *privateKey,
  }

  return &pair, nil

}
