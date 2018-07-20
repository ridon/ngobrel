package id.ngobrel.core;

import org.junit.Test;
import org.junit.Assert;

import java.security.InvalidKeyException;

public class MessageExamplePayloadTest {
  String url = "http://olala";
  String contentType = "olala/omama";
  String fileName = "osama.olala";

  HashId targetNull = null;
  HashId target1 = new HashId("8d74beec1be996322ad76813bafb92d40839895d6dd7ee808b17ca201eac98be".getBytes());
  byte[] contents = "okaka omama orama odama".getBytes();

  public MessageExamplePayloadTest() throws InvalidKeyException {
  }

  @Test
  public void encodeDecodeType0Test() throws Exception {
    MessageExamplePayload t0 = new MessageExamplePayload(target1, contents);
    byte[] encoded = t0.encode();

    MessageExamplePayload t0_1 = MessageExamplePayload.decode(encoded);
    Assert.assertEquals(t0.type, t0_1.type);
    Assert.assertArrayEquals(t0.contents, t0_1.contents);

    t0 = new MessageExamplePayload(targetNull, contents);
    encoded = t0.encode();

    t0_1 = MessageExamplePayload.decode(encoded);
    Assert.assertEquals(t0.type, t0_1.type);
    Assert.assertArrayEquals(t0.contents, t0_1.contents);
  }

  @Test
  public void encodeDecodeType1Test() throws Exception {
    MessageExamplePayload t = new MessageExamplePayload(target1, url, contentType, fileName, contents);
    byte[] encoded = t.encode();

    MessageExamplePayload t_1 = MessageExamplePayload.decode(encoded);
    Assert.assertEquals(t.type, t_1.type);
    Assert.assertEquals(t.url, t_1.url);
    Assert.assertEquals(t.contentType, t_1.contentType);
    Assert.assertEquals(t.fileName, t_1.fileName);
    Assert.assertArrayEquals(t.target.raw(), target1.raw());
    Assert.assertArrayEquals(t.target.raw(), t_1.target.raw());
    Assert.assertArrayEquals(t.contents, t_1.contents);

    t = new MessageExamplePayload(targetNull, url, contentType, fileName, contents);
    encoded = t.encode();

    t_1 = MessageExamplePayload.decode(encoded);
    Assert.assertEquals(t.type, t_1.type);
    Assert.assertEquals(t.url, t_1.url);
    Assert.assertEquals(t.contentType, t_1.contentType);
    Assert.assertEquals(t.fileName, t_1.fileName);
    Assert.assertEquals(t.target, t_1.target);
    Assert.assertArrayEquals(t.contents, t_1.contents);
  }

  @Test
  public void encodeDecodeType2Test() throws Exception {
    MessageExamplePayload t = new MessageExamplePayload(contents);
    byte[] encoded = t.encode();

    MessageExamplePayload t_1 = MessageExamplePayload.decode(encoded);
    Assert.assertEquals(t.type, t_1.type);
    Assert.assertArrayEquals(t.contents, t_1.contents);
  }
}