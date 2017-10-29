package xeddsa

import (
  "crypto/rand"
)

type SignedPreKey struct {
  PreKey KeyPair
  Signature [64]byte
}

func NewSignedPreKey(identityKey PrivateKey) (*SignedPreKey, error) {
  random := rand.Reader

  preKey, err := Generate(random)
  if err != nil {
    return nil, err
  }
  sig := identityKey.Sign(random, preKey.PublicKey.Encode())
  ret := &SignedPreKey{ *preKey, *sig}

  return ret, nil
}
