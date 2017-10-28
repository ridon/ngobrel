package xeddsa
import (
  "crypto/sha512"
  "encoding/hex"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/crypto/xeddsa/internal/edwards25519"
  "io"
)

type PrivateKey struct {
  key [keysize]byte
}

func (t *PrivateKey) HexString() string{
  return hex.EncodeToString(t.key[:])
}

func NewPrivateKey(key [keysize]byte) *PrivateKey {
  ret := PrivateKey {
    key: key,
  }
  return &ret
}

func (t *PrivateKey) GetEd25519PublicKey() [keysize]byte {
  var A edwards25519.ExtendedGroupElement
	var publicKey [keysize]byte
	edwards25519.GeScalarMultBase(&A, &t.key)
	A.ToBytes(&publicKey)

  return publicKey;
}

func (t *PrivateKey) Sign(random io.Reader, message []byte) *[keysize * 2]byte {
  var randomByte [keysize * 2]byte
	io.ReadFull(random, randomByte[:])

  initData := make([]byte, keysize)
  for i := range initData {
    initData[i] = 0xff
  }

  var hash[keysize * 2]byte
	digest := sha512.New()
	digest.Write(initData[:])
	digest.Write(t.key[:])
	digest.Write(message)
	digest.Write(randomByte[:])
	digest.Sum(hash[:0])

  var hashReduced [keysize]byte
	edwards25519.ScReduce(&hashReduced, &hash)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &hashReduced)

	var encodedR[keysize]byte
	R.ToBytes(&encodedR)

  edPubKey := t.GetEd25519PublicKey()

  var hramDigest [keysize * 2]byte
	digest.Reset()
	digest.Write(encodedR[:])
	digest.Write(edPubKey[:])
	digest.Write(message)
	digest.Sum(hramDigest[:0])
	var hramDigestReduced [keysize]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

  var s [keysize]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &t.key, &hashReduced)

	ret := new([keysize * 2]byte)
	copy(ret[:], encodedR[:])
	copy(ret[keysize:], s[:])
	ret[keysize * 2 -1] |= edPubKey[keysize - 1] & 0x80

  return ret;
}

