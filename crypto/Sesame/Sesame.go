package Sesame
import (
  "crypto/rand"
  "crypto/sha256"
  "encoding/binary"
  "errors"
  "github.com/ridon/ngobrel/crypto/Key"
  "github.com/ridon/ngobrel/crypto/Ratchet"
  "github.com/ridon/ngobrel/crypto/X3dh"
  "time"
)

const RidonSig = 0x201711
const RidonSesameSharedKey = "RidonSesame-SharedKey"
const RidonSecretMessage = "R"
type HashId [64]byte

type Contact struct {
  Id string
  Devices []Device
  StaleDate time.Time
}

type Device struct {
  Id HashId
  PublicKey Key.Public
  ActiveSession *Session
  InactiveSessions []Session
  StaleDate time.Time
}

type SelfDevice struct {
  Id HashId
  KeyPair *Key.Pair
  Bundle *Key.Bundle
  UserId string
}

type sharedKey struct {
  key []byte
  preKeyId [32]byte
}

type SessionSecret struct {
  Data [32]byte // FIXME remove?
  Size uint64
  Message []byte
}

type Session struct {
  SelfBundle *Key.Bundle
  RemoteName string
  RemotePublic map[HashId]Key.BundlePublic
  Ratchets map[HashId]Ratchet.Ratchet
  Secrets map[HashId]SessionSecret
}

func NewSelfDevice(id HashId, userId string) (*SelfDevice, error) {
  random := rand.Reader
  pair, err := Key.Generate(random)
  if err != nil {
    return nil, err
  }

  bundle, err := Key.NewBundle(random)
  if err != nil {
    return nil, err
  }
  bundle.PopulatePreKeys(random, 100)
  s := SelfDevice {
    Id: id,
    UserId: userId,
    KeyPair: pair,
    Bundle: bundle,
  }

  return &s, nil
}

// Gets a session secret between our own private bundle and recipient 
// bundle map by device id
func (s *Session) populateSessionSecrets(isSender bool) error {
  random := rand.Reader
  ephKey, err := Key.Generate(random)
  if err != nil {
    return err
  }

  s.Secrets  = make(map[HashId]SessionSecret)
  s.Ratchets = make(map[HashId]Ratchet.Ratchet)
  for id, v := range s.RemotePublic {
    s.Ratchets[id] = *Ratchet.NewRatchet()
    r := s.Ratchets[id]

    if (isSender) {
      k, preKeyId, err := X3dh.GetSharedKeySender(random, ephKey, s.SelfBundle, &v, RidonSesameSharedKey)
      m := []byte(RidonSecretMessage)
      ad := sha256.Sum256(append(s.SelfBundle.Public.Identity.Encode()[:], v.Identity.Encode()[:]...))
      message, err := X3dh.NewMessage(&s.SelfBundle.Public.Identity, &ephKey.PublicKey, *preKeyId, k, m, ad[:])
      if err != nil {
        return err
      }

      encoded := message.EncodeMessage()
      s.Secrets[id] = SessionSecret {
        Data: ad,
        Size: uint64(len(encoded)),
        Message: encoded,
      }
      p := s.RemotePublic[id].Spk.PublicKey
      r.InitSelf(random, &p, k)
    } else {
      s.Secrets[id] = SessionSecret {
      }
    }
    s.Ratchets[id] = r
  }
  return nil
}

func NewSession(selfBundle *Key.Bundle, remoteName string, remote map[HashId]Key.BundlePublic) *Session {
  s := Session {
    SelfBundle: selfBundle,
    RemoteName: remoteName,
    RemotePublic: remote,
  }
  return &s
}

func (s *Session) InitSender() {
  _ = s.populateSessionSecrets(true)
}

func (s *Session) initReceiver(id HashId, message []byte) ([]byte, error) {
  sig := binary.LittleEndian.Uint64(message[0:8])
  if sig != uint64(RidonSig) {
    return nil, errors.New("Data signature invalid")
  }
  size := binary.LittleEndian.Uint64(message[8:16])
  msg := message[16:16 + size]
  data := message[16 + size:]

  err := s.populateSessionSecrets(false)
  if err != nil {
    return nil, err
  }
  pub := s.RemotePublic[id]
  ms, err := X3dh.DecodeMessage(msg)
  if err != nil {
    return nil, err
  }

  k, err := X3dh.GetSharedKeyRecipient(ms, s.SelfBundle, &pub, RidonSesameSharedKey)
  if err != nil {
    return nil, err
  }

  pair := Key.Pair {
    PrivateKey: s.SelfBundle.Private.Spk,
    PublicKey: s.SelfBundle.Public.Spk.PublicKey,
  }
  r := s.Ratchets[id]
  r.InitRemote(&pair, k)
  s.Ratchets[id] = r
  ad := sha256.Sum256(append(pub.Identity.Encode(), s.SelfBundle.Public.Identity.Encode()[:]...))
  s.Secrets[id] = SessionSecret {
    Data: ad,
  }
  return data, nil
}

func (s *Session) Encrypt(id HashId, data []byte) ([]byte, error){
  secrets, ok := s.Secrets[id]
  if ok == false {
    return nil, errors.New("Session is not available")
  }

  ratchet, ok := s.Ratchets[id]
  if ok == false {
    return nil, errors.New("Ratchet is not available")
  }

  msg, err := ratchet.Encrypt(data, secrets.Data[:])
  if err != nil {
    return nil, err
  }

  ret := make([]byte, 0)
  if secrets.Size > 0 && secrets.Size == uint64(len(secrets.Message)) {
    sz := make([]byte, 8)
    binary.LittleEndian.PutUint64(sz, uint64(RidonSig))
    ret = append(ret[:], sz...)
    binary.LittleEndian.PutUint64(sz, secrets.Size)
    ret = append(ret[:], sz...)
    ret = append(ret[:], secrets.Message...)
  }
  ret = append(ret[:], msg...)

  return ret, nil
}

func (s *Session) Decrypt(id HashId, data []byte) ([]byte, error){
  secrets, ok := s.Secrets[id]
  if ok == false {
    msgdata, err := s.initReceiver(id, data)
    if err != nil {
      return nil, err //errors.New("Session is not available")
    }
    secrets = s.Secrets[id]
    data = msgdata
  }

  ratchet, ok := s.Ratchets[id]
  if ok == false {
    return nil, errors.New("Ratchet is not available")
  }

  msg, err := ratchet.Decrypt(data, secrets.Data[:])
  if err != nil {
    return nil, err
  }
  return msg, nil
}
