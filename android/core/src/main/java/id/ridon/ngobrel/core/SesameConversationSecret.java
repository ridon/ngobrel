package id.ridon.ngobrel.core;

/**
 * This class represents a Sesame conversation secret
 */

class SesameConversationSecret {
  int size = 0;
  byte[] message = new byte[0];
  byte[] ad = new byte[0];

  SesameConversationSecret(byte[] message, int size, byte[] ad) {
    this.size = size;
    this.ad = ad;
    this.message = message;
  }

  SesameConversationSecret() {
    // Empty
  }

  SesameConversationSecret(byte[] ad) {
    this.ad = ad;
  }


}
