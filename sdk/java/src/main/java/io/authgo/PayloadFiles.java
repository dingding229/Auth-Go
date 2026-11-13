package io.authgo;

import static io.authgo.Client.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** The Go payload file format: authenticate each independent 1 MiB GCM chunk. */
public final class PayloadFiles {
  public static final int CHUNK_SIZE = 1 << 20;

  private PayloadFiles() {}

  public record File(String name, String kind, String path, long size, String mainClass) {}

  public static List<File> files(Payload payload) {
    try {
      Payload p = payload.validated();
      List<File> files = new ArrayList<>();
      for (Object value : list(obj(parse(decode(p.manifest()))).get("files"))) {
        var item = obj(value);
        files.add(
            new File(
                str(item, "name"),
                str(item, "kind"),
                str(item, "path"),
                Payload.integer(item.get("size")).longValueExact(),
                str(item, "main_class")));
      }
      return List.copyOf(files);
    } catch (Exception failure) {
      throw Payload.invalid();
    }
  }

  public static long payloadCipherSize(long size) {
    if (size < 0 || size > Long.MAX_VALUE / 2) throw Payload.invalid();
    return Math.addExact(
        size, Math.multiplyExact(16, Math.max(1, (size + CHUNK_SIZE - 1) / CHUNK_SIZE)));
  }

  public static void decryptPayloadFile(
      OutputStream target, byte[] ciphertext, Payload payload, byte[] key, int index)
      throws IOException {
    if (ciphertext == null) throw Payload.invalid();
    decryptPayloadFile(
        target, new ByteArrayInputStream(ciphertext), ciphertext.length, payload, key, index);
  }

  /** No unauthenticated block is written. Discard partial output on any failure. */
  public static void decryptPayloadFile(
      OutputStream target, InputStream source, long total, Payload payload, byte[] key, int index)
      throws IOException {
    List<File> files = files(payload);
    if (index < 0
        || index >= files.size()
        || key == null
        || key.length != 32
        || source == null
        || target == null) throw Payload.invalid();
    long size = files.get(index).size();
    if (total != payloadCipherSize(size)) throw Payload.invalid();
    byte[] binding = payload.payloadBinding(), ciphertext = new byte[CHUNK_SIZE + 16];
    long count = Math.max(1, (size + CHUNK_SIZE - 1) / CHUNK_SIZE);
    try {
      Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
      for (long j = 0; j < count; j++) {
        int n = (int) Math.min(CHUNK_SIZE, size - j * CHUNK_SIZE);
        if (source.readNBytes(ciphertext, 0, n + 16) != n + 16) throw Payload.invalid();
        byte[] nonce = ByteBuffer.allocate(12).putInt(index).putLong(j).array();
        byte[] aad =
            concat(
                bytes("authgo-payload-chunk-v1\0"),
                binding,
                nonce,
                new byte[] {(byte) (j == count - 1 ? 1 : 0)});
        cipher.init(
            Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
        cipher.updateAAD(aad);
        byte[] plain = cipher.doFinal(ciphertext, 0, n + 16);
        try {
          target.write(plain);
        } finally {
          Arrays.fill(plain, (byte) 0);
        }
      }
      if (source.read() != -1) throw Payload.invalid();
    } catch (java.security.GeneralSecurityException failure) {
      throw Payload.invalid();
    } finally {
      Arrays.fill(ciphertext, (byte) 0);
    }
  }
}
