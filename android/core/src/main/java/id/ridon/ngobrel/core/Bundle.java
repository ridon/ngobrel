package id.ridon.ngobrel.core;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class Bundle {
  public final BundlePrivate bundlePrivate;
  public final BundlePublic bundlePublic;

  Bundle() throws IllegalDataSizeException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
    KeyPair pair = new KeyPair();
    SignedPreKey spk = new SignedPreKey(pair.privateKey);

    bundlePrivate = new BundlePrivate(pair.privateKey, spk.getPrivateKey());
    bundlePublic = new BundlePublic(pair.publicKey, spk.getPublic());
  }

  void populatePreKeys() throws IllegalDataSizeException, NoSuchAlgorithmException, InvalidKeyException {
    for (int i = 0; i < Constants.MaxPreKeys; i ++) {
      KeyPair pair = new KeyPair();
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      md.update(pair.publicKey.raw());
      PreKeyId id = new PreKeyId(md.digest());

      bundlePrivate.insert(id, pair.privateKey);
      bundlePublic.insert(id, pair.publicKey);
    }
  }
}
