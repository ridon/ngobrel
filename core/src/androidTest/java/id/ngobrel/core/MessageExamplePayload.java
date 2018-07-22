package id.ngobrel.core;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;

import id.ngobrel.core.HashId;
import id.ngobrel.core.IllegalDataSizeException;

/**
 * This is an example of message payload sent back and forth in the protocol
 */
public class MessageExamplePayload {
  //
  // This is unique id
  HashId messageId;

  /*
    Type is:
    0 plain message
    1 media message
    2 sender key message
    3 handshake message
   */
  int type;

  /*
  All fields below are not filled except in the following cases:

  # plain message
    target: only applicable when quoting, refer to messageId of the quoted message
    contents: the message

  # media message
    target: only applicable when quoting, refer to messageId of the quoted message
    contents: encryption key
    url: public URL where the media can be downloaded
    contentType: the content type of the media
    fileName: the file name of the media

  # sender key message:
    contents: the sender key

   */
  HashId target;
  byte[] contents; // the actual payload

  String url;
  String contentType;
  String fileName;


  // Plain Message
  public MessageExamplePayload(HashId target, byte[] contents) {
    this.target = target;
    this.contents = contents;
    this.type = 0;
  }

  // Media Message
  public MessageExamplePayload(HashId target, String url, String contentType, String fileName, byte[] encryptionKey) {
    this.target = target;
    this.type = 1;
    this.url = url;
    this.contentType = contentType;
    this.fileName = fileName;
    this.contents = encryptionKey;
  }

  // Sender Key Message
  public MessageExamplePayload(byte[] senderKey) {
    this.type = 2;
    this.contents = senderKey;
  }

  // Handshake Message
  public MessageExamplePayload() {
    this.type = 3;
  }

  byte[] encode() throws IOException {
    ByteArrayOutputStream output = new ByteArrayOutputStream();
    ByteBuffer buffer = ByteBuffer.allocate(4);
    buffer.putInt(type);
    output.write(buffer.array());

    buffer = ByteBuffer.allocate(4);
    buffer.putInt(contents.length);
    output.write(buffer.array());

    output.write(contents);

    buffer = ByteBuffer.allocate(4);
    if (target == null) {
      buffer.putInt(0);
      output.write(buffer.array());
    } else {
      buffer.putInt(target.raw().length);
      output.write(buffer.array());
      output.write(target.raw());
    }

    if (type == 1) { // media message
      buffer = ByteBuffer.allocate(4);
      buffer.putInt(url.getBytes().length);
      output.write(buffer.array());
      output.write(url.getBytes());

      buffer = ByteBuffer.allocate(4);
      buffer.putInt(contentType.getBytes().length);
      output.write(buffer.array());
      output.write(contentType.getBytes());

      buffer = ByteBuffer.allocate(4);
      buffer.putInt(fileName.getBytes().length);
      output.write(buffer.array());
      output.write(fileName.getBytes());
    }

    return output.toByteArray();

  }

  private static byte[] getData(ByteArrayInputStream input) throws IllegalDataSizeException, IOException {
    byte[] b = new byte[4];
    input.read(b);
    ByteBuffer buffer = ByteBuffer.wrap(b);
    int size = buffer.getInt();

    if (size <= 0) {
      throw new IllegalDataSizeException();
    }

    byte[] data = new byte[size];
    input.read(data);

    return data;
  }

  private static HashId getHashId(ByteArrayInputStream input) throws InvalidKeyException, IOException {
    try {
      byte[] hashId = getData(input);
      return new HashId(hashId);
    } catch (IllegalDataSizeException x) {
      return null;
    }
  }

  private static String getString(ByteArrayInputStream input) throws IllegalDataSizeException, IOException {
    return new String(getData(input));
  }

  public static final MessageExamplePayload decode(byte[] msg) throws IllegalDataSizeException, IOException, InvalidKeyException {
    ByteArrayInputStream input = new ByteArrayInputStream(msg);
    byte[] b = new byte[4];
    input.read(b);
    ByteBuffer buffer = ByteBuffer.wrap(b);
    int type = buffer.getInt();

    byte[] contents = getData(input);

    if (type == 2) { // sender key message
      return new MessageExamplePayload(contents);
    }

    HashId target = getHashId(input);

    if (type == 0) { // plain message
      return new MessageExamplePayload(target, contents);
    }

    String url = getString(input);
    String contentType = getString(input);
    String fileName = getString(input);

    return new MessageExamplePayload(target, url, contentType, fileName, contents);
  }
}
