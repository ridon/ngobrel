package aead

import (
  "bytes"
  "crypto/aes"
  "crypto/cipher"
  "crypto/hmac"
  "crypto/sha512"
  "errors"
  "github.com/ridon/ngobrel/core/Kdf"
)

func generateKeys(key []byte, info string) ([32]byte, [32]byte, [16]byte, error) {
  var empty [32]byte
  var empty16 [16]byte
  hashFn := sha512.New
  salt := make([]byte, hashFn().Size())
  kdf, err := Kdf.KDF(hashFn, key[:], salt, info, 80)
  if err != nil {
    return empty, empty, empty16, err
  }

  var encKey [32]byte
  var authKey [32]byte
  var iv [16]byte
  copy(encKey[:], kdf[:32])
  copy(authKey[:], kdf[32:64])
  copy(iv[:], kdf[64:])
  return encKey, authKey, iv, nil
}

func Encrypt(key []byte, plainText []byte, ad []byte, info string) ([]byte, error) {

  encKey, authKey, iv, err := generateKeys(key, info)
  if err != nil {
    return nil, err
  }

  c, err := aes.NewCipher(encKey[:])
  if err != nil {
    return nil, err
  }
  encrypter := cipher.NewCBCEncrypter(c, iv[:])

  plainTextLen := len(plainText)
	padLen := 16 - plainTextLen % 16
	padded := make([]byte, plainTextLen + padLen)
	copy(padded, plainText)
	for i := 0; i < padLen; i++ {
		padded[plainTextLen + i] = byte(padLen)
	}
  encrypter.CryptBlocks(padded, padded)

  mac := hmac.New(sha512.New, authKey[:])
  mac.Write(ad)
  mac.Write(padded)
  sum := mac.Sum(nil)

  ret := append(padded[:], sum[:]...)
  return ret, nil

}

func Decrypt(key []byte, cipherText []byte, ad []byte, info string) ([]byte, error) {

  hashFn := sha512.New
  encKey, authKey, iv, err := generateKeys(key, info)
  if err != nil {
    return nil, err
  }

  c, err := aes.NewCipher(encKey[:])
  if err != nil {
    return nil, err
  }

  size := hashFn().Size()
  pos := len(cipherText) - size
  check := make([]byte, size)
  copy(check[:], cipherText[pos:])

  mac := hmac.New(sha512.New, authKey[:])
  mac.Write(ad)
  mac.Write(cipherText[:pos])
  sum := mac.Sum(nil)

  if !bytes.Equal(sum, check) {
    return nil, errors.New("Unable to authenticate the encrypted data")
  }

  result := cipherText[:pos]
  decrypter := cipher.NewCBCDecrypter(c, iv[:])
  decrypter.CryptBlocks(result, result)

  // https://gist.github.com/dmichael/5751886
  resultLen := len(result)
  endIndex := int(result[resultLen-1])

  if endIndex <= 16 {
    if 1 < endIndex {
      for i := resultLen - endIndex; i < resultLen; i++ {
        if result[resultLen-1] != result[i] {
          return nil, errors.New("Unpad error")
        }
      }
    }

    return result[:resultLen-endIndex], nil
  }

  return nil, errors.New("Unpad error")
}
