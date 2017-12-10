package Key
import (
  "crypto/sha512"
  "encoding/hex"
  "hash"
  "github.com/ridon/ngobrel/core/Kdf"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/core/Key/internal/edwards25519"
  "golang.org/x/crypto/curve25519"
  "io"
)

type Private [32]byte

func (t *Private) Encode() [32 + 1]byte {
  var ret [32+1]byte
  ret[0] = 0x5
  copy(ret[1:], t[:])
  return ret
}

func (t *Private) HexString() string{
  return hex.EncodeToString(t[:])
}

func NewPrivate(key [32]byte) *Private {
  ret := Private(key)
  return &ret
}

func (t *Private) GetEd25519PublicKey() [32]byte {
  var A edwards25519.ExtendedGroupElement
	var publicKey [32]byte
  var slice [32]byte
  copy(slice[:], t[:])
  edwards25519.GeScalarMultBase(&A, &slice)
	A.ToBytes(&publicKey)

  return publicKey;
}

func (t *Private) Sign(random io.Reader, message []byte) [64]byte {
  var randomByte [64]byte
	io.ReadFull(random, randomByte[:])

  initData := make([]byte, 32)
  for i := range initData {
    initData[i] = 0xff
  }

  var hash[64]byte
	digest := sha512.New()
	digest.Write(initData[:])
	digest.Write(t[:])
	digest.Write(message)
	digest.Write(randomByte[:])
	digest.Sum(hash[:0])

  var hashReduced [32]byte
	edwards25519.ScReduce(&hashReduced, &hash)
	var R edwards25519.ExtendedGroupElement
	edwards25519.GeScalarMultBase(&R, &hashReduced)

	var encodedR[32]byte
	R.ToBytes(&encodedR)

  edPubKey := t.GetEd25519PublicKey()

  var hramDigest [64]byte
	digest.Reset()
	digest.Write(encodedR[:])
	digest.Write(edPubKey[:])
	digest.Write(message)
	digest.Sum(hramDigest[:0])
	var hramDigestReduced [32]byte
	edwards25519.ScReduce(&hramDigestReduced, &hramDigest)

  var s [32]byte
  var slice[32]byte
  copy(slice[:], t[:])
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &slice, &hashReduced)

	var ret [64]byte
	copy(ret[:], encodedR[:])
	copy(ret[32:], s[:])
	ret[63] |= edPubKey[31] & 0x80

  return ret;
}

func (t *Private) ShareSecret(withOther Public) [32]byte {
  var s [32]byte
  copy(s[:], t[:])

  var r [32]byte
  copy(r[:], withOther[:])

  var sharedSecret [32]byte
  curve25519.ScalarMult(&sharedSecret, &s, &r)

	return sharedSecret
}

func (t *Private) DeriveKey(withOther Public, hashFn func() hash.Hash, info string, length int) ([]byte, error) {
  shared := t.ShareSecret(withOther)

  salt := make([]byte, hashFn().Size())
  return Kdf.KDF(hashFn, shared[:32], salt, info, length)
}

func (t *Private) Clear() {
  for i := 0; i < len(t); i ++ {
    t[i] = 0
  }
}
