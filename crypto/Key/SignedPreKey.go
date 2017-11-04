package Key

import (
  "crypto/rand"
)

type SignedPreKey struct {
  PreKey Pair
  Signature [64]byte
}

func NewSignedPreKey(identityKey Private) (*SignedPreKey, error) {
  random := rand.Reader

  preKey, err := Generate(random)
  if err != nil {
    return nil, err
  }
  sig := identityKey.Sign(random, preKey.PublicKey.Encode())
  ret := &SignedPreKey{ *preKey, sig}

  return ret, nil
}

