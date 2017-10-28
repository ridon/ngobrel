package x3dh

import (
  "github.com/ridon/ngobrel/crypto/xeddsa"
  "golang.org/x/crypto/hkdf"
  "hash"
  "io"
)

func KDF(hashFn func() hash.Hash, secret []byte, info string) []byte {
  initData := make([]byte, xeddsa.Keysize)
  for i := range initData {
    initData[i] = 0xff
  }

  data := make([]byte, 32 + len(secret))
  copy(data[:], initData[:])
  copy(data[32:], secret[:])
  salt := make([]byte, hashFn().Size())
  infoByte := []byte(info)

  fn := hkdf.New(hashFn, data, salt, infoByte)
  kdf := make([]byte, 32)
  n, _ := io.ReadFull(fn, kdf)
  if (n != 32) {
    return nil
  }
  return kdf
}

