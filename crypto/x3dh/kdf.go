package x3dh

import (
  "golang.org/x/crypto/hkdf"
  "hash"
  "io"
)

func KDF(hashFn func() hash.Hash, secret []byte, info string, length int) ([]byte, error) {
  initData := make([]byte, 32)
  for i := range initData {
    initData[i] = 0xff
  }

  data := make([]byte, 32 + len(secret))
  copy(data[:], initData[:])
  copy(data[32:], secret[:])
  salt := make([]byte, hashFn().Size())
  infoByte := []byte(info)

  fn := hkdf.New(hashFn, data, salt, infoByte)
  kdf := make([]byte, length)
  n, err := io.ReadFull(fn, kdf)
  if err != nil {
    return nil, err
  }
  if n != 32 {
    return nil, err
  }
  return kdf, err
}

