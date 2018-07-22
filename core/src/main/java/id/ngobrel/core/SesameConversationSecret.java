package id.ngobrel.core;

/**
 * This class represents a Sesame conversation secret
 */

public class SesameConversationSecret {
  int size = 0;
  byte[] message = new byte[0];
  byte[] ad = new byte[0];

  public SesameConversationSecret(byte[] message, int size, byte[] ad) {
    this.size = size;
    this.ad = ad;
    this.message = message;
  }

  public SesameConversationSecret() {
    // Empty
  }

  public SesameConversationSecret(byte[] ad) {
    this.ad = ad;
  }


}
