package xeddsa
import (
  "crypto/rand"
  "crypto/sha512"
  "encoding/hex"
  "hash"
  "github.com/ridon/ngobrel/crypto/x3dh"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/crypto/xeddsa/internal/edwards25519"
  "io"
)

type PrivateKey [Keysize]byte

func (t *PrivateKey) Encode() [Keysize + 1]byte {
  var ret [Keysize+1]byte
  ret[0] = 0x5
  copy(ret[1:], t[:])
  return ret
}

func (t *PrivateKey) HexString() string{
  return hex.EncodeToString(t[:])
}

func NewPrivateKey(key [Keysize]byte) *PrivateKey {
  ret := PrivateKey(key)
  return &ret
}

func (t *PrivateKey) GetEd25519PublicKey() [Keysize]byte {
  var A edwards25519.ExtendedGroupElement
	var publicKey [Keysize]byte
  var slice [Keysize]byte
  copy(slice[:], t[:])
  edwards25519.GeScalarMultBase(&A, &slice)
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
	digest.Write(t[:])
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
  var slice[Keysize]byte
  copy(slice[:], t[:])
	edwards25519.ScMulAdd(&s, &hramDigestReduced, &slice, &hashReduced)

	ret := new([Keysize * 2]byte)
	copy(ret[:], encodedR[:])
	copy(ret[Keysize:], s[:])
	ret[Keysize * 2 -1] |= edPubKey[Keysize - 1] & 0x80

  return ret;
}

func (t *PrivateKey) ShareSecret(withOther PublicKey) [32]byte {
  var key [Keysize]byte;
  copy(key[:], t[:])
  return x3dh.GenerateSharedSecret(withOther, key)
}

func (t *PrivateKey) DeriveKey(withOther PublicKey, hashFn func() hash.Hash, info string, length int) ([]byte, error) {
  shared := t.ShareSecret(withOther)

  return x3dh.KDF(hashFn, shared[:32], info, length)
}

func (t *PrivateKey) SignPreKey() (*[Keysize * 2]byte, error) {
  random := rand.Reader
  var x, err = Generate(random)
  if err != nil {
    return nil, err
  }

  sig := t.Sign(random, x.PublicKey.Encode())
  return sig, nil
}
