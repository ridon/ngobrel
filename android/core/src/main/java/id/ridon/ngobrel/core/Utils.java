package id.ridon.ngobrel.core;

class Utils {
  public static String hexString(byte[] data) {
    char[] hexArray = "0123456789ABCDEF".toCharArray();
    char[] hexChars = new char[data.length * 2];
    for (int j = 0; j < data.length; j++) {
      int v = data[j] & 0xFF;
      hexChars[j * 2] = hexArray[v >>> 4];
      hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    }
    return new String(hexChars);
  }

  public static byte[] fromHexString(String s) {
    int length = s.length();
    byte[] data = new byte[length / 2];
    for (int i = 0; i < length; i += 2) {
      data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) +
                             Character.digit(s.charAt(i+1), 16));
    }
    return data;
  }
}
