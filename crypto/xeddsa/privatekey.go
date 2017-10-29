package xeddsa
import (
  "crypto/sha512"
  "encoding/hex"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/crypto/xeddsa/internal/edwards25519"
  "io"
)

type PrivateKey struct {
  Contents [Keysize]byte
}

func (t *PrivateKey) HexString() string{
  return hex.EncodeToString(t.Contents[:])
}

func NewPrivateKey(key [Keysize]byte) *PrivateKey {
  ret := PrivateKey {
    Contents : key,
  }
  return &ret
}

func (t *PrivateKey) GetEd25519PublicKey() [Keysize]byte {
  var A edwards25519.ExtendedGroupElement
	var publicKey [Keysize]byte
	edwards25519.GeScalarMultBase(&A, &t.Contents)
	A.ToBytes(&publicKey)

  return publicKey;
}

func (t *PrivateKey) Sign(random io.Reader, message []byte) *[Keysize * 2]byte {
  var randomByte [Keysize * 2]byte
	io.ReadFull(random, randomByte[:])

  initData := make([]byte, Keysize)
  for i := range initData {
    initData[i] = 0xff
  }

  var hash[Keysize * 2]byte
	digest := sha512.New()
	digest.Write(initData[:])
	digest.Write(t.Contents[:])
	digest.Write(message)
	digest.Write(randomByte[:])
	digest.Sum(hash[:0])

  var hashReduced [Keysize]byte
	edwards25519.ScReduce(&hashReduced, &hash)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &hashReduced)

	var encodedR[Keysize]byte
	R.ToBytes(&encodedR)

  edPubKey := t.GetEd25519PublicKey()

  var hramDigest [Keysize * 2]byte
	digest.Reset()
	digest.Write(encodedR[:])
	digest.Write(edPubKey[:])
	digest.Write(message)
	digest.Sum(hramDigest[:0])
	var hramDigestReduced [Keysize]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

  var s [Keysize]byte
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &t.Contents, &hashReduced)

	ret := new([Keysize * 2]byte)
	copy(ret[:], encodedR[:])
	copy(ret[Keysize:], s[:])
	ret[Keysize * 2 -1] |= edPubKey[Keysize - 1] & 0x80

  return ret;
}

