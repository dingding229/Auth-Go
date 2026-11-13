package io.authgo;

import static io.authgo.Client.*;
import java.util.*;
import java.nio.file.*;
import java.io.*;

/** Private authenticated v2 index. No offsets or paths are taken from public metadata. */
final class PayloadWatermark {
  record Entry(List<String> path,List<Long> offsets) {}
  record File(int index,List<Entry> entries) {}
  record Index(String tag,List<File> files) {}
  record Patch(byte[] target,int offset) {}
  static long decimal(Object value,long limit) {
    String s=Payload.text(value);
    if(!s.matches("0|[1-9][0-9]{0,18}"))throw Payload.invalid();
    try {long n=Long.parseLong(s);if(n>limit)throw Payload.invalid();return n;}catch(NumberFormatException e){throw Payload.invalid();}
  }
  static String safe(Object value) {
    String s=Payload.text(value);
    if(s.isEmpty() || s.matches("(?s).*[\\\\:\\x00-\\x1f\\x7f].*"))throw Payload.invalid();
    for(String p:s.split("/",-1))if(p.isEmpty()||p.equals(".")||p.equals(".."))throw Payload.invalid();
    return s;
  }
  static byte[] response(Object value) {
    if(!(value instanceof String s) || !s.matches("[0-9a-f]{64}") || s.equals("0".repeat(64)))throw fail("SDK_RESPONSE_INVALID");
    return HexFormat.of().parseHex(s);
  }
  static boolean material(Payload p,byte[] value) {
    if(p.v()!=2 || value==null || value.length!=64)return false;
    int all=0;for(int i=32;i<64;i++)all|=value[i];if(all==0)return false;
    return true;
  }
  // Schema-aware reader caps arrays before allocation, including malformed authenticated indices.
  static final class Reader {
    final String s; int at,files,entries,offsets;
    Reader(byte[] raw){if(raw==null||raw.length<1||raw.length>(8<<20))throw Payload.invalid();s=new String(raw,java.nio.charset.StandardCharsets.UTF_8);if(!Arrays.equals(raw,bytes(s)))throw Payload.invalid();}
    void ws(){while(at<s.length()&&" \r\n\t".indexOf(s.charAt(at))>=0)at++;}
    boolean peek(char c){ws();return at<s.length()&&s.charAt(at)==c;}
    void take(char c){if(!peek(c))throw Payload.invalid();at++;}
    String text(){take('"');int start=at-1;while(at<s.length()){char c=s.charAt(at++);if(c=='\\'){at++;continue;}if(c=='"')return Payload.text(parse(bytes(s.substring(start,at))));}throw Payload.invalid();}
    List<Object> array(String name){take('[');List<Object> out=new ArrayList<>();if(peek(']')){at++;return out;}for(;;){
      switch(name){case "files"->{if(++files>65535)throw Payload.invalid();}case "entries"->{if(++entries>65535)throw Payload.invalid();}case "offsets"->{if(++offsets>65535)throw Payload.invalid();}case "path"->{if(out.size()>=8)throw Payload.invalid();}default->throw Payload.invalid();}
      out.add(name.equals("files")?object("index","entries"):name.equals("entries")?object("path","offsets"):text());
      if(peek(']')){at++;return out;}take(',');}}
    Map<String,Object> object(String... fields){take('{');Set<String> keys=Set.of(fields);Map<String,Object> out=new HashMap<>();for(;;){String key=text();if(!keys.contains(key)||out.containsKey(key))throw Payload.invalid();take(':');out.put(key,Set.of("files","entries","path","offsets").contains(key)?array(key):text());if(peek('}')){at++;if(out.size()!=keys.size())throw Payload.invalid();return out;}take(',');}}
  }
  static Index parseIndex(byte[] raw,List<PayloadFiles.File> publicFiles) {
    try {
      Reader r=new Reader(raw);var root=r.object("v","tag","files");r.ws();String tag=Payload.text(root.get("tag"));
      if(r.at!=r.s.length()||!root.get("v").equals("1")||!tag.matches("[0-9a-f]{32}")||publicFiles.isEmpty()||publicFiles.size()>65535)throw Payload.invalid();
      Set<Integer> seen=new HashSet<>();List<File> files=new ArrayList<>();
      for(Object item:list(root.get("files"))){var f=obj(item);int i=(int)decimal(f.get("index"),65534);if(i>=publicFiles.size()||!seen.add(i)||publicFiles.get(i).kind().equals("watermark"))throw Payload.invalid();
        String kind=publicFiles.get(i).kind();Set<List<String>> paths=new HashSet<>();List<Entry> entries=new ArrayList<>();int slots=0;
        for(Object val:list(f.get("entries"))){var e=obj(val);List<String> path=new ArrayList<>();for(Object v:list(e.get("path")))path.add(safe(v));
          if(!paths.add(path.stream().map(p->p.toLowerCase(Locale.ROOT)).toList()) || (switch(kind){case "node","protect"->!path.isEmpty();case "python","php","dotnet"->path.size()!=1;case "java"->path.isEmpty();default->true;}))throw Payload.invalid();
          if(kind.equals("dotnet")&&(path.get(0).contains("/")||!path.get(0).toLowerCase(Locale.ROOT).endsWith(".dll")))throw Payload.invalid();
          List<Long> offsets=new ArrayList<>();long last=-96;for(Object v:list(e.get("offsets"))){long n=decimal(v,Long.MAX_VALUE/2);if(n<last+96||path.isEmpty()&&n+96>publicFiles.get(i).size())throw Payload.invalid();offsets.add(n);last=n;}
          if(offsets.isEmpty())throw Payload.invalid();slots+=offsets.size();entries.add(new Entry(List.copyOf(path),List.copyOf(offsets)));}
        if(slots<8)throw Payload.invalid();files.add(new File(i,List.copyOf(entries)));}
      if(files.isEmpty())throw Payload.invalid();for(int i=0;i<publicFiles.size();i++)if(!publicFiles.get(i).kind().equals("watermark")&&!seen.contains(i))throw Payload.invalid();
      return new Index(tag,List.copyOf(files));
    }catch(Exception e){throw Payload.invalid();}
  }
  static List<Patch> prepare(Map<List<String>,byte[]> targets,Index index,int fileIndex) {
    File selected=index.files().stream().filter(f->f.index()==fileIndex).findFirst().orElseThrow(Payload::invalid);
    byte[] expected=bytes(index.tag()+"0".repeat(64));List<Patch> pending=new ArrayList<>();
    for(Entry e:selected.entries()){byte[] target=targets.get(e.path());if(target==null)throw Payload.invalid();for(long offset:e.offsets()){
      if(offset>target.length-96)throw Payload.invalid();int n=(int)offset;for(int j=0;j<96;j++)if(target[n+j]!=expected[j])throw Payload.invalid();pending.add(new Patch(target,n+32));}}
    return pending;
  }
  static void apply(List<Patch> pending,byte[] material) {
    if(material==null||material.length!=64)throw Payload.invalid();int nonzero=0;for(int i=32;i<64;i++)nonzero|=material[i];if(nonzero==0)throw Payload.invalid();
    byte[] hex=bytes(HexFormat.of().formatHex(material,32,64));try{for(Patch p:pending)System.arraycopy(hex,0,p.target(),p.offset(),64);}finally{Arrays.fill(hex,(byte)0);}
  }
  static Index read(Path directory,Payload p,byte[] material) throws IOException {
    if(!material(p,material))throw Payload.invalid();var files=PayloadFiles.files(p);
    for(int i=0;i<files.size();i++)if(files.get(i).kind().equals("watermark")){
      var f=files.get(i);byte[] key=Arrays.copyOf(material,32),raw=null;
      try(var source=java.nio.channels.FileChannel.open(directory.resolve(f.path()),StandardOpenOption.READ,LinkOption.NOFOLLOW_LINKS);var out=new SealedClassLoader.WipingBuffer()){
        PayloadFiles.decryptPayloadFile(out,java.nio.channels.Channels.newInputStream(source),source.size(),p,key,i);raw=out.toByteArray();return parseIndex(raw,files);
      }finally{Arrays.fill(key,(byte)0);if(raw!=null)Arrays.fill(raw,(byte)0);}}
    throw Payload.invalid();
  }
}
