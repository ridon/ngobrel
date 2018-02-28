package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

/**
 * This class represents a Sesame sender device
 */
public class SesameSenderDevice {
  public HashId id;
  KeyPair pair;
  Bundle bundle;
  String userId;

  public SesameSenderDevice(HashId id, String userId) throws IllegalDataSizeException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    pair = new KeyPair();
    bundle = new Bundle();
    bundle.populatePreKeys();
    this.id = id;
    this.userId = userId;
  }

  public Bundle getBundle() {
    return bundle;
  }


}
