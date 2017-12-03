package Sesame
import (
  "bytes"
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

func (h *HashId) HashIdEquals(other HashId) bool {
  return bytes.Equal(h[:], other[:])
}

type Contact struct {
  Id string
  Devices map[HashId]Device
  ActiveSession []HashId
  StaleDate time.Time
}
type Contacts map[string]Contact

type Device struct {
  Id HashId
  PublicKey *Key.Public
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

type ConversationSecret struct {
  Data [32]byte // FIXME remove?
  Size uint64
  Message []byte
}

type Conversation struct {
  SelfBundle *Key.Bundle
  SelfName string
  RemoteName string
  RemotePublic map[HashId]Key.BundlePublic
  Ratchets map[HashId]Ratchet.Ratchet
  Secrets map[HashId]ConversationSecret
  Contacts *Contacts
}

type MessageBundle map[HashId][]byte
type Message struct {
  Id [64]byte
  Time time.Time
  Data []byte
  Sender string
  SenderDeviceId HashId
}

func InitDevice(id HashId, device *Device) map[HashId]Device {
  d := make(map[HashId]Device)
  d[id] = *device
  return d
}

func NewContacts() Contacts {
  return make(Contacts)
}

func (c Contacts) AddContact(contact Contact) {
  c[contact.Id] = contact
}

func (c Contacts) AddDevice(id string, device *Device) {
  _, ok := c[id]
  if ok == false {
    c[id] = Contact {
      Id: id,
    }
  }
  if c[id].Devices == nil {
    c[id] = Contact {
      Id: id,
      Devices: make(map[HashId]Device),
    }
  }
  c[id].Devices[device.Id] = *device
  activeSessions := make([]HashId, 0)
  activeSessions = append(activeSessions[:], device.Id)
  for _, v := range c[id].Devices {
    if device.Id != v.Id {
      activeSessions = append(activeSessions[:], device.Id)
    }
  }
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
func (s *Conversation) populateConversationSecrets(isSender bool) error {
  random := rand.Reader
  ephKey, err := Key.Generate(random)
  if err != nil {
    return err
  }

  s.Secrets  = make(map[HashId]ConversationSecret)
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
      s.Secrets[id] = ConversationSecret {
        Data: ad,
        Size: uint64(len(encoded)),
        Message: encoded,
      }
      p := s.RemotePublic[id].Spk.PublicKey
      r.InitSelf(random, &p, k)
    } else {
      s.Secrets[id] = ConversationSecret {
      }
    }
    s.Ratchets[id] = r
  }
  return nil
}

func NewConversation(selfName string, contacts *Contacts, selfBundle *Key.Bundle, remoteName string, remote map[HashId]Key.BundlePublic) *Conversation {
  s := Conversation {
    SelfName: selfName,
    SelfBundle: selfBundle,
    RemoteName: remoteName,
    RemotePublic: remote,
    Contacts: contacts,
  }
  return &s
}

func (s *Conversation) InitSender() {
  _ = s.populateConversationSecrets(true)
}

func (s *Conversation) initReceiver(id HashId, message []byte) ([]byte, error) {
  sig := binary.LittleEndian.Uint64(message[0:8])
  if sig != uint64(RidonSig) {
    return nil, errors.New("Data signature invalid")
  }
  size := binary.LittleEndian.Uint64(message[8:16])
  msg := message[16:16 + size]
  data := message[16 + size:]

  err := s.populateConversationSecrets(false)
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
  s.Secrets[id] = ConversationSecret {
    Data: ad,
  }
  return data, nil
}

func (s *Conversation) prepEncrypt() {
  if s.SelfName == s.RemoteName {
    return
  }
  // Encryption preparation 
  contacts := *s.Contacts
  c, ok := contacts[s.RemoteName]
  if ok != false {
    // Contact exists
    timeNil := time.Time{}
    // 1. Delete stale records
    if c.StaleDate == timeNil {
      delete(contacts, s.RemoteName)
    }
    if c.Devices == nil {
      // Empty devices
      c.Devices = make(map[HashId]Device)
      for idRemote, vRemote := range s.RemotePublic {
        c.Devices[idRemote] = Device {
          Id: idRemote,
          PublicKey: &vRemote.Identity,
        }
      }
    } else {
      // 2. Check public key value 
      for idRemote, vRemote := range s.RemotePublic {
        for idLocal, vLocal := range c.Devices {
          if idLocal == idRemote {
            // 3. Delete local record if not the same with remote
            if vLocal.PublicKey != nil && !vRemote.Identity.PublicKeyEquals(vLocal.PublicKey) {
              delete(c.Devices, idLocal)
              c.Devices[idLocal] = Device {
                Id: idLocal,
                PublicKey: &vRemote.Identity,
              }
            }
          }
        }
      }
    }
  } else {
    // Contact doesn't exist, add it
    contacts[s.RemoteName] = Contact {
      Id: s.RemoteName,
      Devices: make(map[HashId]Device),
      StaleDate: time.Time{},
    }
    for idRemote, vRemote := range s.RemotePublic {
      contacts[s.RemoteName].Devices[idRemote] = Device {
        Id: idRemote,
        PublicKey: &vRemote.Identity,
      }
    }
  }
  s.Contacts = &contacts
}

func (s *Conversation) Encrypt(data []byte) (*MessageBundle, error) {
  s.prepEncrypt()
  ret := make(MessageBundle)
  contact := *s.Contacts

  // use an active session if any
  if len(contact[s.RemoteName].ActiveSession) > 0 {
    id := contact[s.RemoteName].ActiveSession[0]
    msg, err := s.encrypt(id, data)
    if err != nil {
      return nil, err
    }
    ret[id] = msg
  } else {
    // Prepare for all devices
    for id, _ := range s.Secrets {
      msg, err := s.encrypt(id, data)
      if err != nil {
        return nil, err
      }
      ret[id] = msg
    }
  }
  return &ret, nil
}

func (s *Conversation) encrypt(id HashId, data []byte) ([]byte, error){
  secrets, ok := s.Secrets[id]
  if ok == false {
    return nil, errors.New("Conversation is not available")
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

func (s *Conversation) resetActiveSession(id HashId) {
  secrets, ok := s.Secrets[id]
  if ok && len(secrets.Message) > 0 {
    // clears X3DH message if any
    secrets.Message = make([]byte, 0)
    s.Secrets[id] = secrets
  }
  list := make([]HashId, 0)
  list = append(list[:], id)
  c := *s.Contacts
  contact := c[s.RemoteName]
  for _, v := range contact.ActiveSession {
    if !id.HashIdEquals(v) {
      list = append(list[:], v)
    }
  }
  contact.ActiveSession = list
  c[s.RemoteName] = contact
  s.Contacts = &c
}

func (s *Conversation) Decrypt(message Message) ([]byte, error){
  secrets, ok := s.Secrets[message.SenderDeviceId]
  data := message.Data
  if ok == false {
    msgData, err := s.initReceiver(message.SenderDeviceId, data)
    if err != nil {
      return nil, err //errors.New("Conversation is not available")
    }
    secrets = s.Secrets[message.SenderDeviceId]
    data = msgData
  }

  ratchet, ok := s.Ratchets[message.SenderDeviceId]
  if ok == false {
    return nil, errors.New("Ratchet is not available")
  }

  msg, err := ratchet.Decrypt(data, secrets.Data[:])
  if err != nil {
    return nil, err
  }
  s.resetActiveSession(message.SenderDeviceId)
  return msg, nil
}

