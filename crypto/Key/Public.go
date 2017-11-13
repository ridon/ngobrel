package Key
import (
  "bytes"
  "encoding/hex"
  "errors"
  // ED25519 from golang/crypto/x
  "github.com/ridon/ngobrel/crypto/Key/internal/ed25519"
  "github.com/ridon/ngobrel/crypto/Key/internal/edwards25519"
)

type Public [32]byte

func (t *Public) Encode() []byte {
  return append([]byte{0x5}, t[:]...)
}

func (t *Public) RawPublic() [32]byte {
  return *t
}

func (t *Public) PublicKeyEquals(other *Public) bool {
  if other == nil {
    return false
  }
  return bytes.Equal(t[:], other[:])
}

func DecodePublic(data[]byte, offset int) (*Public, error) {
  if data[offset] == 0x5 {
    key := [32]byte{}
    copy(key[:], data[offset + 1:])
    return NewPublic(key), nil
  }
  return nil, errors.New("Keytype is not known")
}

func (t *Public) HexString() string{
  return hex.EncodeToString(t[:])
}

func NewPublic(key [32]byte) *Public {
  ret := Public(key)
  return &ret
}

func (t *Public) Verify(message []byte, signature [64]byte) bool {
  var key [32]byte;
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
