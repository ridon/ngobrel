package Key
import (
  "crypto/sha256"
  "io"
)

type BundleKey [32]byte
type BundlePrivate struct {
  Identity Private
  Spk Private
  PreKeys map[BundleKey]Private
}

type BundlePublic struct {
  Identity Public
  Spk SignedPreKeyPublic
  PreKeys map[BundleKey]Public
}

type Bundle struct {
  Private BundlePrivate
  Public BundlePublic
}

func NewBundle(random io.Reader) (*Bundle, error) {
  id, err := Generate(random)

  if err != nil {
    return nil, err
  }

  spk, err := NewSignedPreKey(id.PrivateKey)

  if err != nil {
    return nil, err
  }

  priv := BundlePrivate{
    Identity: id.PrivateKey,
    Spk: spk.PrivateKey,
  }

  pub := BundlePublic {
    Identity: id.PublicKey,
    Spk: spk.Public,
  }

  bundle := Bundle{
    Private: priv,
    Public: pub,
  }

  return &bundle, nil
}

func (b *Bundle) PopulatePreKeys(random io.Reader, size int) {
  
  b.Private.PreKeys = make(map[BundleKey]Private)
  b.Public.PreKeys = make(map[BundleKey]Public)
  for i := 0; i < size; i ++ {
    p, err := Generate(random) 
    if err == nil {
      h := sha256.Sum256(p.PublicKey[:])

      b.Private.PreKeys[h] = p.PrivateKey
      b.Public.PreKeys[h] = p.PublicKey
    }
  }
}

func (b *BundlePublic) PopPreKey() ([32]byte, *Public) {
  var empty [32]byte
  if len(b.PreKeys) == 0 {
    return empty, nil
  }

  for k := range b.PreKeys {
    popped := b.PreKeys[k]
    delete(b.PreKeys, k)
    return k, &popped
  }
  return empty, nil
}

func (b *BundlePublic) Verify() bool {
  return b.Spk.Verify(b.Identity);
}

func (b *BundlePrivate) FetchPreKey(id [32]byte) *Private {
  if len(b.PreKeys) == 0 {
    return nil
  }

  ret, ok := b.PreKeys[id]
  if ok {
    delete(b.PreKeys, id)
    return &ret
  }
  return nil
}


