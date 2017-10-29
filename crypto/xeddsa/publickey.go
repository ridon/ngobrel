package xeddsa
import (
  "encoding/hex"
  "errors"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/crypto/xeddsa/internal/ed25519"
  "github.com/ridon/ngobrel/crypto/xeddsa/internal/edwards25519"
)

type PublicKey [Keysize]byte

func (t *PublicKey) Encode() []byte {
  return append([]byte{0x5}, t[:]...) 
}

func Decode(data[]byte, offset int) (*PublicKey, error) {
  if data[offset] == 0x5 {
    key := [Keysize]byte{}
    copy(key[:], data[offset + 1:])
    return NewPublicKey(key), nil
  }
  return nil, errors.New("Keytype is not known")
}


func (t *PublicKey) HexString() string{
  return hex.EncodeToString(t[:])
}

func NewPublicKey(key [Keysize]byte) *PublicKey {
  ret := PublicKey(key)
  return &ret
}

func (t *PublicKey) Verify(message []byte, signature [64]byte) bool {
  var key [Keysize]byte;
  copy(key[:], t[:])
  key[31] &= 0x7F

	var edY, one, montX, montXMinusOne, montXPlusOne edwards25519.FieldElement
	edwards25519.FeFromBytes(&montX, &key)
	edwards25519.FeOne(&one)
	edwards25519.FeSub(&montXMinusOne, &montX, &one)
	edwards25519.FeAdd(&montXPlusOne, &montX, &one)
	edwards25519.FeInvert(&montXPlusOne, &montXPlusOne)
	edwards25519.FeMul(&edY, &montXMinusOne, &montXPlusOne)

	var A_ed [32]byte
	edwards25519.FeToBytes(&A_ed, &edY)

	A_ed[31] |= signature[63] & 0x80
	signature[63] &= 0x7F

  return ed25519.Verify(A_ed, message, signature)
}
