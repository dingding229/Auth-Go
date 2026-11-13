package io.authgo;

import java.nio.file.*;
import java.util.*;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public final class Vectors {

  static Map<String, Object> read(String name) throws Exception {
    return Client.obj(
      Client.parse(Files.readAllBytes(Path.of("sdk/vectors/" + name)))
    );
  }

  static byte[] hex(Object s) {
    return HexFormat.of().parseHex(s.toString());
  }

  static void check(boolean v) {
    if (!v) throw new AssertionError("vector mismatch");
  }

  public static void main(String[] args) throws Exception {
    var v = read("v2.json");
    var h = read("hkdf.json");
    check(
      HexFormat.of()
        .formatHex(
          Client.hkdf(
            hex(h.get("ikm_hex")),
            hex(h.get("salt_hex")),
            hex(h.get("info_hex")),
            Integer.parseInt(
              h
                .get("length")
                .toString()
                .replace("JsonNumber[lexeme=", "")
                .replace("]", "")
            )
          )
        )
        .equals(h.get("okm_hex"))
    );
    byte[] shared = Client.shared(
        hex(v.get("ephemeral_private_hex")),
        Client.decode(v.get("gateway_public").toString())
      ),
      aad = hex(v.get("request_aad_hex"));
    for (String direction : List.of("request", "response"))
      check(
        HexFormat.of()
          .formatHex(
            Client.hkdf(
              shared,
              Client.digest(aad),
              Client.bytes("authgo/v2/" + direction),
              32
            )
          )
          .equals(v.get(direction + "_key_hex"))
      );
    var request = Client.obj(v.get("request"));
    byte[] padding = Client.open(
      hex(v.get("request_key_hex")),
      Client.decode(request.get("n").toString()),
      Client.decode(request.get("c").toString()),
      aad
    );
    check(HexFormat.of().formatHex(padding).equals(v.get("padding_hex")));
    check(
      new String(
        Client.unpad(padding),
        java.nio.charset.StandardCharsets.UTF_8
      ).equals(v.get("inner"))
    );
    var response = Client.obj(v.get("response"));
    check(
      new String(
        Client.unpad(
          Client.open(
            hex(v.get("response_key_hex")),
            Client.decode(response.get("n").toString()),
            Client.decode(response.get("c").toString()),
            hex(v.get("response_aad_hex"))
          )
        ),
        java.nio.charset.StandardCharsets.UTF_8
      ).equals(v.get("response_plain"))
    );
    var inner = Client.obj(
      Client.parse(Client.bytes(v.get("inner").toString()))
    );
    String raw = v.get("inner").toString();
    int start = raw.indexOf("\"body\":") + 7;
    String body = raw.substring(start, raw.length() - 1);
    Mac mac = Mac.getInstance("HmacSHA256");
    mac.init(new SecretKeySpec(Client.bytes("test-secret-only"), "HmacSHA256"));
    check(
      HexFormat.of()
        .formatHex(
          mac.doFinal(
            Client.bytes(
              inner.get("op").toString() +
                inner.get("timestamp") +
                inner.get("nonce") +
                Client.hash(Client.bytes(body))
            )
          )
        )
        .equals(inner.get("signature"))
    );
    var pub = Client.decode(v.get("ed25519_public").toString());
    String[] p = v.get("ticket").toString().split("\\.");
    check(
      Client.verifySignature(
        pub,
        Client.concat(Client.bytes("authgo-ticket-v2\0"), Client.decode(p[0])),
        Client.decode(p[1])
      )
    );
    check(!Client.verifySignature(pub, Client.concat(Client.bytes("invalid-domain\0"), Client.decode(p[0])), Client.decode(p[1])));
    byte[] key = Client.hkdf(
      hex(v.get("unlock_seed_hex")),
      new byte[0],
      Client.bytes("authgo-unlock-v2\0" + v.get("unlock_label")),
      32
    );
    check(HexFormat.of().formatHex(key).equals(v.get("unlock_key_hex")));
    p = v.get("resource").toString().split("\\.");
    check(
      new String(
        Client.open(
          key,
          Client.decode(p[1]),
          Client.decode(p[2]),
          Client.bytes("authgo-resource-v2\0settings")
        )
      ).equals("hello")
    );
    var u = read("update-response.json");
    List<Object> updates = new ArrayList<>();
    updates.add(u);
    updates.addAll(Client.list(u.get("docker_cases")));
    for (Object item : updates) {
      var x = Client.obj(item);
      var env = Client.obj(x.get("response"));
      String canonical = Client.canonical(
        Client.map(
          "code",
          env.get("code"),
          "data",
          env.get("data"),
          "ts",
          env.get("ts")
        )
      );
      check(canonical.equals(x.get("canonical_signed")));
      check(
        Client.verifySignature(
          Base64.getDecoder().decode(x.get("public_key").toString()),
          Client.bytes(canonical),
          Base64.getDecoder().decode(x.get("signature").toString())
        )
      );
    }
    var e = read("error-classification.json");
    for (Object item : Client.list(e.get("cases"))) {
      var x = Client.obj(item);
      check(
        new Client.AuthGoException(
          x.get("code").toString(),
          Boolean.TRUE.equals(x.get("authenticated")),
          null
        ).refusal() == Boolean.TRUE.equals(x.get("clear_cache"))
      );
    }
    for (Object item : Client.list(e.get("update_cases")))
      check(!Boolean.TRUE.equals(Client.obj(item).get("clear_cache")));
    for (Object item : Client.list(read("fingerprint.json").get("cases"))) {
      var c = Client.obj(item);
      check(
        Client.identityHash(
          c.get("machine").toString(),
          c.get("mac").toString(),
          c.get("cpu").toString()
        ).equals(c.get("expected"))
      );
    }
    for (Object item : Client.list(read("license-key.json").get("cases"))) {
      var c = Client.obj(item);
      boolean valid = true;
      try {
        Client.validateKey(Client.str(c, "key"));
      } catch (Client.AuthGoException error) {
        valid = false;
        check(error.code.equals(c.get("code")));
      }
      check(valid == Boolean.TRUE.equals(c.get("valid")));
    }
    for (Object item : Client.list(
      read("fingerprint.json").get("cpuinfo_cases")
    )) {
      var c = Client.obj(item);
      String cpu = Client.parseLinuxCPU(Client.str(c, "cpuinfo"));
      check(cpu.equals(c.get("cpu")));
      if (!cpu.isEmpty()) check(
        Client.identityHash(
          Client.str(c, "machine"),
          Client.str(c, "mac"),
          cpu
        ).equals(c.get("expected"))
      );
    }
    System.out.println(
      "{\"language\":\"java\",\"license_key_vectors\":16,\"cpuinfo_vectors\":8,\"result\":\"PASS\"}"
    );
    var c = read("canonical.json");
    check(
      Client.canonical(
        Client.parse(Client.bytes(c.get("raw").toString()))
      ).equals(c.get("canonical"))
    );
    check(
      Client.verifySignature(
        Base64.getDecoder().decode(c.get("public_key").toString()),
        Client.bytes(c.get("canonical").toString()),
        Base64.getDecoder().decode(c.get("signature").toString())
      )
    );
    for (Object bad : Client.list(c.get("invalid"))) {
      boolean refused = false;
      try {
        Client.parse(Client.bytes(bad.toString()));
      } catch (Client.AuthGoException expected) {
        refused = true;
      }
      check(refused);
    }
    var container=Client.obj(Client.parse(Files.readAllBytes(Path.of("sdk/vectors/container-identity.json"))));
    for(Object value:Client.list(container.get("detection"))){var containerCase=Client.obj(value);var files=Client.obj(containerCase.get("files"));Map<String,String> env=new HashMap<>();Client.obj(containerCase.get("env")).forEach((k,x)->env.put(k,x.toString()));check(ContainerIdentity.detect(sourcePath->files.containsKey(sourcePath)?Client.bytes(files.get(sourcePath).toString()):null,env)==Client.yes(containerCase,"expected"));}
    for(Object value:Client.list(container.get("fingerprints"))){var containerCase=Client.obj(value);check(ContainerIdentity.hash(Client.str(containerCase,"id")).equals(Client.str(containerCase,"expected")));}
    var session=Client.obj(read("instance-session.json").get("instance_session"));
    check(Client.decode(Client.str(session,"valid")).length==Client.num(session,"bytes"));
    for(Object value:Client.list(session.get("invalid"))){boolean valid=false;try{valid=Client.decode(value.toString()).length==Client.num(session,"bytes");}catch(Client.AuthGoException ignored){}check(!valid);}
    check(!Client.yes(session,"persist_in_cache"));
    GuardTests.run();
    PayloadTests.run();
    SealedTests.run();
    System.out.println("{\"language\":\"java\",\"vectors\":\"PASS\"}");
  }
}
