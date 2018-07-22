package id.ngobrel.core;

import java.nio.charset.StandardCharsets;
import at.favre.lib.crypto.HKDF;

public class Kdf {
  byte[] key;

  byte[] prepareData(byte[] secret, byte[] salt) {
    byte[] data;

    data = new byte[32 + secret.length];
    for (int i = 0; i < 32; i ++) {
      data[i] = -1;
    }
    System.arraycopy(secret, 0, data, 32, secret.length);

    return data;
  }

  public static Kdf KdfSha512(byte[] secret, byte[] salt) {
    Kdf kdf = new Kdf();

    byte[] data = kdf.prepareData(secret, salt);
    kdf.key = HKDF.fromHmacSha512().extract(salt, data);

    return kdf;
  }

  public byte[] get(final String info, int length) {
    return HKDF.fromHmacSha512().expand(key, info.getBytes(StandardCharsets.UTF_8), length);
  }
}