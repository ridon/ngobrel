package id.ridon.ngobrel.core;

import java.nio.charset.StandardCharsets;

public final class Constants {
  public static final String RidonSalt = "RidonSalt";
  public static final int MaxPreKeys = 10;
  public static final String X3DhMessageInfo = "RidonX3DMessage";
  public static final String RidonRatchetInfo = "Ridon";
  public static final int MaxSkippedMessages = 1024 * 1024;
  public static final String RidonSesameSharedKey = "RidonSesame-SharedKey";
  public static final String RidonSecretMessage = "R";
  public static final int RidonMagix = 0x201801;

  public static byte[] getRidonSalt512() {
    byte[] salt = new byte[64];
    System.arraycopy(RidonSalt.getBytes(StandardCharsets.UTF_8), 0, salt, 0,  RidonSalt.length() > 64 ? 64 : RidonSalt.length());
    return salt;
  }



}
