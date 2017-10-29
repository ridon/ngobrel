package xeddsa

import (
  "crypto/sha512"
  "encoding/hex"
  "fmt"
  "testing"
  "crypto/rand"
)

func TestGenerate(t *testing.T) {
  var x, _ = Generate(rand.Reader)

  if x == nil ||
    len(x.PublicKey) == 0 ||
    len(x.PrivateKey) == 0 {
    t.Error("Key was not generated");
  }

  if x.PublicKey.HexString() == x.PrivateKey.HexString() {
    t.Error("Public key was not computed correctly")
  }

  fmt.Printf("-->%s\n", x.PrivateKey.HexString())
  fmt.Printf("-->%s\n", x.PublicKey.HexString())

}

func TestSignVerify(t *testing.T) {
  var x, _ = Generate(rand.Reader)
  data := []byte("omama")
  sig := x.PrivateKey.Sign(rand.Reader, data)
  if (x.PublicKey.Verify(data, *sig) == false) {
    t.Error("Signature can't be verified")
  }
  data[0] &= 0x80;
  if (x.PublicKey.Verify(data, *sig) == true) {
    t.Error("Signature can't be verified after altered")
  }
  fmt.Printf("-->%s\n", hex.EncodeToString(sig[:]))
}

func TestEncodeDecode(t *testing.T) {
  var x, _ = Generate(rand.Reader)
  encoded := x.PublicKey.Encode()
  pk, _ := Decode(encoded, 0)
  if pk == nil {
    t.Error("Can't decode encoded public key")
  }
  if pk.HexString() != x.PublicKey.HexString() {
    t.Error("Can't decode encoded public key")
  }
}

func TestSharedSecret(t *testing.T) {
  aliceKey,_ := Generate(rand.Reader)
  bobKey,_ := Generate(rand.Reader)

  aliceShared := aliceKey.PrivateKey.ShareSecret(bobKey.PublicKey)
  bobShared := bobKey.PrivateKey.ShareSecret(aliceKey.PublicKey)

  if (aliceShared != bobShared) {
    t.Error("Shared secrets not computed correctly")
  }
}

func TestDeriveKey(t *testing.T) {
  aliceKey,_ := Generate(rand.Reader)
  bobKey,_ := Generate(rand.Reader)

  info := "Ridon"
  aliceDerived, _ := aliceKey.PrivateKey.DeriveKey(bobKey.PublicKey, sha512.New, info, 64)
  bobDerived, _ := bobKey.PrivateKey.DeriveKey(aliceKey.PublicKey, sha512.New, info, 64)

  if hex.EncodeToString(aliceDerived) != hex.EncodeToString(bobDerived) {
    t.Error("Shared secrets not computed correctly")
  }
}

func TestSignedPreKey(t *testing.T) {
  aliceKey,_ := Generate(rand.Reader)

  spk, err := NewSignedPreKey(aliceKey.PrivateKey)

  if err != nil {
    t.Error("Error when creating SPK")
  }

  data := spk.PreKey.PublicKey.Encode()
  if aliceKey.PublicKey.Verify(data, spk.Signature) == false {
    t.Error("SPK is not verified")
  }
}
