package io.authgo;

import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Function;

final class ContainerIdentity {
  static final String SESSION = Client.b64(Client.random(16));
  static final Set<String> REPLACED = ConcurrentHashMap.newKeySet();
  static final Map<String,String> MEMORY = new ConcurrentHashMap<>();
  static boolean detect(Function<String,byte[]> read, Map<String,String> env) {
    String force=env.get("AUTHGO_CONTAINER");
    if("0".equals(force)||"1".equals(force))return "1".equals(force);
    for(String p:List.of("/.dockerenv","/run/.containerenv"))try{if(read.apply(p)!=null)return true;}catch(RuntimeException ignored){}
    try {String raw=new String(read.apply("/proc/1/cgroup"), java.nio.charset.StandardCharsets.UTF_8);return List.of("docker","containerd","kubepods","libpod").stream().anyMatch(raw::contains);}catch(RuntimeException e){return false;}
  }
  static boolean detect(){return detect(p->{try{return Files.readAllBytes(Path.of(p));}catch(Exception e){return null;}},System.getenv());}
  static String hash(String id){return Client.hash(Client.bytes("authgo/instance/v1\0"+id));}
  record Identity(String id, boolean memory){}
  static String read(Path p) throws Exception {
    if(!Files.isRegularFile(p,LinkOption.NOFOLLOW_LINKS)||Files.size(p)!=64)throw new Exception();
    if(p.getFileSystem().supportedFileAttributeViews().contains("posix")&&!Files.getPosixFilePermissions(p).equals(PosixFilePermissions.fromString("rw-------")))throw new Exception();
    String id=Files.readString(p);if(!id.matches("[0-9a-f]{64}"))throw new Exception();return id;
  }
  static Identity load(Path dir){
    try {
      if(dir.toString().isEmpty())throw new Exception();
      Files.createDirectories(dir);Path target=dir.resolve("instance-id");
      if(Files.exists(target,LinkOption.NOFOLLOW_LINKS))return new Identity(read(target),false);
      Path temp=Files.createTempFile(dir,".instance-","");
      try {
        if(dir.getFileSystem().supportedFileAttributeViews().contains("posix"))Files.setPosixFilePermissions(temp,PosixFilePermissions.fromString("rw-------"));
        Files.writeString(temp,java.util.HexFormat.of().formatHex(Client.random(32)));
        try{Files.createLink(target,temp);}catch(FileAlreadyExistsException ignored){}
      }finally{Files.deleteIfExists(temp);}
      return new Identity(read(target),false);
    }catch(Exception e){return new Identity(MEMORY.computeIfAbsent(dir.toAbsolutePath().toString(), k->java.util.HexFormat.of().formatHex(Client.random(32))),true);}
  }
  private ContainerIdentity(){}
}
