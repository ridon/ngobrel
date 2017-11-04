package Key

import (
  "crypto/rand"
)

type SignedPreKeyPublic struct {
  PublicKey Public
  Signature [64]byte
}

type SignedPreKey struct {
  PrivateKey Private
  Public SignedPreKeyPublic
}

func NewSignedPreKey(identityKey Private) (*SignedPreKey, error) {
  random := rand.Reader

  preKey, err := Generate(random)
  if err != nil {
    return nil, err
  }
  sig := identityKey.Sign(random, preKey.PublicKey.Encode())
  public := SignedPreKeyPublic{
    PublicKey: preKey.PublicKey,
    Signature: sig,
  }
  ret := &SignedPreKey{
    PrivateKey: preKey.PrivateKey,
    Public: public,
  }

  return ret, nil
}

func (s *SignedPreKeyPublic) Verify(pub Public) bool {
  data := s.PublicKey.Encode()
  return pub.Verify(data, s.Signature)
}
