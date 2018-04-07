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
}
