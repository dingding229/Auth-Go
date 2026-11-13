package io.authgo;

import static io.authgo.Client.*;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.util.*;
import java.util.regex.*;

/** Language-neutral content-key cache only. Never reads/writes launcher proof files. */
final class PayloadCache {
  static final String PREFIX="AUTHGO-PAYLOAD-CACHE-v2.";
  static final Set<PosixFilePermission> MODE=PosixFilePermissions.fromString("rw-------");
  final Path directory;
  final String identity,base;
  final String fingerprint;
  PayloadCache(Path directory,String endpoint,String appKey,String fingerprint,byte[] publicKey) {
    this.directory=directory;this.fingerprint=fingerprint;
    Matcher m=Pattern.compile("^(https?://)([^/?#]*)",Pattern.CASE_INSENSITIVE).matcher(endpoint);
    String normalized=m.find()?m.group(1).toLowerCase(Locale.ROOT)+m.group(2).toLowerCase(Locale.ROOT)+endpoint.substring(m.end()):endpoint;
    identity=normalized+"\0"+appKey+"\0"+fingerprint+"\0"+hash(publicKey);
    base="authgo-payload-v2-"+hash(bytes(identity))+"-";
  }
  record Material(Path file,byte[] key,byte[] aad) implements AutoCloseable {
    public void close(){Arrays.fill(key,(byte)0);}
  }
  Material material(Payload payload,Map<String,Object> grant,long now,boolean disabled) {
    if(disabled)throw fail("SDK_CACHE_UNAVAILABLE");
    if(grant.get("issued_at")==null || grant.get("grace_until")==null)throw fail("SDK_CACHE_INVALID");
    long issued=date(grant.get("issued_at")), grace=date(grant.get("grace_until"));
    if(yes(grant,"is_trial") || grace<=issued || now>=grace || issued>now+300)throw fail("SDK_GRACE_EXPIRED");
    if(grant.get("starts_at")!=null&&now<date(grant.get("starts_at")))throw fail("LICENSE_NOT_STARTED");
    if(now>=date(grant.get("expires_at")))throw fail("LICENSE_EXPIRED");
    String seed=str(grant,"unlock_hash");if(!seed.matches("[0-9a-fA-F]{64}"))throw fail("SDK_CACHE_INVALID");
    BigInteger id=Payload.integer(grant.get("license_id"));if(id.signum()<=0 || id.bitLength()>64)throw fail("SDK_CACHE_INVALID");
    byte[] label=payload.cacheLabel(fingerprint),hash=digest(label);
    byte[] key=hkdf(HexFormat.of().parseHex(seed),new byte[0],concat(bytes("authgo-unlock-v2\0"),label),32);
    return new Material(directory.resolve(base+HexFormat.of().formatHex(hash)+".cache"),key,
      concat(bytes("authgo-payload-cache-file-v"+payload.v()+"\0"),hash,ByteBuffer.allocate(8).putLong(id.longValue()).array()));
  }
  void save(Payload payload,Map<String,Object> grant,long now,boolean disabled,byte[] key) {
    if(!PayloadWatermark.material(payload,key))return;
    Path temp=null;
    try(Material m=material(payload,grant,now,disabled)) {
      byte[] nonce=random(12),raw=bytes(PREFIX+b64(concat(nonce,seal(m.key(),nonce,key,m.aad()))));
      Files.createDirectories(directory,PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")));
      if(Files.exists(m.file(),LinkOption.NOFOLLOW_LINKS)&&!Files.isRegularFile(m.file(),LinkOption.NOFOLLOW_LINKS))return;
      temp=Files.createTempFile(directory,".authgo-payload-",".tmp",PosixFilePermissions.asFileAttribute(MODE));
      Files.setPosixFilePermissions(temp,MODE);
      try(FileChannel out=FileChannel.open(temp,StandardOpenOption.WRITE,LinkOption.NOFOLLOW_LINKS)) {
        ByteBuffer data=ByteBuffer.wrap(raw);while(data.hasRemaining())out.write(data);out.force(true);
      }
      Files.move(temp,m.file(),StandardCopyOption.ATOMIC_MOVE,StandardCopyOption.REPLACE_EXISTING);
    }catch(Exception ignored){/* Best effort: unwritable storage must not fail online unlock. */}
    finally{if(temp!=null)try{Files.deleteIfExists(temp);}catch(IOException | SecurityException ignored){/* best effort */}}
  }
  static BasicFileAttributes attributes(Path file) throws IOException {
    BasicFileAttributes info=Files.readAttributes(file,BasicFileAttributes.class,LinkOption.NOFOLLOW_LINKS);
    if(!info.isRegularFile() || info.size()>256 || !Files.getPosixFilePermissions(file,LinkOption.NOFOLLOW_LINKS).equals(MODE))throw new IOException("cache");
    if(file.getFileSystem().supportedFileAttributeViews().contains("unix") && (((Number)Files.getAttribute(file,"unix:mode",LinkOption.NOFOLLOW_LINKS)).intValue()&07777)!=0600)throw new IOException("cache permissions");
    return info;
  }
  byte[] load(Payload payload,Map<String,Object> grant,long now,boolean disabled) {
    try(Material m=material(payload,grant,now,disabled)) {
      byte[] raw;
      try {
        BasicFileAttributes before=attributes(m.file());
        try(FileChannel in=FileChannel.open(m.file(),StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS)) {
          BasicFileAttributes after=attributes(m.file());
          if(before.fileKey()==null || !Objects.equals(before.fileKey(),after.fileKey()) || in.size()!=before.size())throw fail("SDK_CACHE_INVALID");
          ByteBuffer bytes=ByteBuffer.allocate(257);while(bytes.hasRemaining()&&in.read(bytes)>=0) { /* bounded */ }
          raw=Arrays.copyOf(bytes.array(),bytes.position());
          if(!Objects.equals(before.fileKey(),attributes(m.file()).fileKey()))throw fail("SDK_CACHE_INVALID");
        }
      }catch(Client.AuthGoException error){throw error;}
      catch(Exception error){throw fail("SDK_CACHE_UNAVAILABLE");}
      try {
        String prefix=PREFIX;
        String text=new String(raw,java.nio.charset.StandardCharsets.UTF_8);
        if(raw.length>256 || !Arrays.equals(bytes(text),raw) || !text.startsWith(prefix))throw fail("SDK_CACHE_INVALID");
        byte[] encrypted=decode(text.substring(prefix.length()));if(encrypted.length!=92)throw fail("SDK_CACHE_INVALID");
        byte[] key=open(m.key(),Arrays.copyOf(encrypted,12),Arrays.copyOfRange(encrypted,12,encrypted.length),m.aad());
        if(!PayloadWatermark.material(payload,key)){Arrays.fill(key,(byte)0);throw fail("SDK_CACHE_INVALID");}return key;
      }catch(Exception error){throw fail("SDK_CACHE_INVALID");}
    }
  }
  void clear(boolean disabled) {
    if(disabled)return;
    try(DirectoryStream<Path> entries=Files.newDirectoryStream(directory)) {
      for(Path file:entries) {
        String name=file.getFileName().toString();
        if(name.startsWith(base)&&name.endsWith(".cache"))try{Files.deleteIfExists(file);}catch(IOException | SecurityException ignored){/* best effort */}
      }
    }catch(Exception ignored){/* No persistent cache; cleanup must not mask an authorization result. */}
  }
}
