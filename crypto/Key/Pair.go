package Key

import (
  "golang.org/x/crypto/curve25519"
  "io"
)

type Pair struct {
  PublicKey Public
  PrivateKey Private
}

func Generate(random io.Reader) (*Pair, error) {
  var priv, pub [32]byte

  _, err := io.ReadFull(random, priv[:])
	if err != nil {
		return nil, err
	}
  priv[0] &= 248
	priv[31] &= 127
	priv[31] |= 64
  curve25519.ScalarBaseMult(&pub, &priv)

  privateKey := NewPrivate(priv)
  publicKey := NewPublic(pub)
  pair := Pair {
    PublicKey: *publicKey,
    PrivateKey: *privateKey,
  }

  return &pair, nil

}
