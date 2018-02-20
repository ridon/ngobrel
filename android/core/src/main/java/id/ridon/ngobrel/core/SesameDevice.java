package id.ridon.ngobrel.core;

import java.util.Date;

/**
 * This class represents a Sesame device
 */
public class SesameDevice {
  final HashId id;
  final PublicKey publicKey;
  Date staleTime;

  public SesameDevice(HashId id, PublicKey publicKey) {
    this.id = id;
    this.publicKey = publicKey;
  }

  public Date getStaleTime() {
    return staleTime;
  }

  public HashId getId() {
    return id;
  }

  public PublicKey getPublicKey() {
    return publicKey;
  }
}

