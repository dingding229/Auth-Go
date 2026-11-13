<?php
declare(strict_types=1);
namespace AuthGo;

/** @internal Exact, bounded private wire schema; strings only, never public offsets. */
final class PayloadPathAliases
{
    private array $seen=[],$unicode=[];
    public function add(string $path): void {
        $key=strtolower($path);if(isset($this->seen[$key]))throw Payload::invalid();
        $unicode=preg_match('/[^\x00-\x7f]/',$path)===1;
        // PCRE's built-in Unicode caseless matching needs no optional mbstring/intl dependency.
        // ASCII-only archives stay on the hash path; only Unicode aliases require comparisons.
        foreach(($unicode?$this->seen:$this->unicode) as $prior)if(preg_match('~\A'.preg_quote($path,'~').'\z~iu',$prior)!==0)throw Payload::invalid();
        $this->seen[$key]=$path;if($unicode)$this->unicode[$key]=$path;
    }
}
final class PayloadWatermarkReader
{
    private int $at=0;
    private array $counts=['files'=>0,'entries'=>0,'offsets'=>0];
    public function __construct(private string $source) {if(strlen($source)<1||strlen($source)>8388608||preg_match('//u',$source)!==1)throw Payload::invalid();}
    private function ws(): void {while(isset($this->source[$this->at])&&str_contains(" \r\n\t",$this->source[$this->at]))$this->at++;}
    private function peek(string $c): bool {$this->ws();return ($this->source[$this->at]??null)===$c;}
    private function take(string $c): void {if(!$this->peek($c))throw Payload::invalid();$this->at++;}
    private function text(): string {
        $this->take('"');$start=$this->at-1;
        while(isset($this->source[$this->at])){$c=$this->source[$this->at++];if($c==='\\'){$this->at++;continue;}if($c==='"')return Payload::text(Json::parse(substr($this->source,$start,$this->at-$start)));}
        throw Payload::invalid();
    }
    private function readArray(string $name): array {
        $this->take('[');$out=[];if($this->peek(']')){$this->at++;return $out;}
        while(true){if($name==='path'){if(count($out)>=8)throw Payload::invalid();}elseif(++$this->counts[$name]>65535)throw Payload::invalid();
            $out[]=match($name){'files'=>$this->object(['index','entries']),'entries'=>$this->object(['path','offsets']),default=>$this->text()};
            if($this->peek(']')){$this->at++;return $out;}$this->take(',');}
    }
    private function object(array $fields): array {
        $this->take('{');$out=[];
        while(true){$key=$this->text();if(!in_array($key,$fields,true)||array_key_exists($key,$out))throw Payload::invalid();$this->take(':');
            $out[$key]=in_array($key,['files','entries','path','offsets'],true)?$this->readArray($key):$this->text();
            if($this->peek('}')){$this->at++;if(count($out)!==count($fields))throw Payload::invalid();return $out;}$this->take(',');}
    }
    public function read(): array {$out=$this->object(['v','tag','files']);$this->ws();if($this->at!==strlen($this->source))throw Payload::invalid();return $out;}
}
final class PayloadWatermark
{
    public static function response(mixed $value): string {
        if(!is_string($value)||!preg_match('/\A[0-9a-f]{64}\z/D',$value)||$value===str_repeat('0',64))throw new Error('SDK_RESPONSE_INVALID','内容水印响应无效');
        return hex2bin($value);
    }
    public static function material(Payload $p,string $value): bool {return $p->v===2&&strlen($value)===64&&substr($value,32)!==str_repeat("\0",32);}
    private static function decimal(mixed $value,string $limit='4611686018427387903'): int {
        if(PHP_INT_SIZE<8||!is_string($value)||!preg_match('/\A(0|[1-9][0-9]{0,18})\z/D',$value)||Payload::compare($value,$limit)>0)throw Payload::invalid();return (int)$value;
    }
    private static function safe(string $s): void {
        Payload::text($s);if($s===''||preg_match('/[\\\\:\x00-\x1f\x7f]/',$s))throw Payload::invalid();
        foreach(explode('/',$s) as $p)if($p===''||$p==='.'||$p==='..')throw Payload::invalid();
    }
    public static function parse(string $raw,array $public): array {
        try {
            $out=(new PayloadWatermarkReader($raw))->read();
            if($out['v']!=='1'||!preg_match('/\A[0-9a-f]{32}\z/D',$out['tag'])||!$out['files']||!$public||count($public)>65535)throw Payload::invalid();
            $seen=[];
            foreach($out['files'] as &$file){$i=self::decimal($file['index'],'65534');if(!isset($public[$i])||isset($seen[$i])||$public[$i]['kind']==='watermark')throw Payload::invalid();$seen[$i]=true;$kind=$public[$i]['kind'];$paths=new PayloadPathAliases();$slots=0;
                foreach($file['entries'] as &$entry){$path=$entry['path'];foreach($path as $p)self::safe($p);$paths->add(implode("\0",$path));
                    if(match($kind){'node','protect'=>count($path)!==0,'python','php','dotnet'=>count($path)!==1,'java'=>count($path)<1,default=>true})throw Payload::invalid();
                    if($kind==='dotnet'&&(str_contains($path[0],'/')||!str_ends_with(strtolower($path[0]),'.dll')))throw Payload::invalid();
                    $last=-96;if(!$entry['offsets'])throw Payload::invalid();foreach($entry['offsets'] as &$n){$n=self::decimal($n);if($n<$last+96||!$path&&$n+96>(int)Payload::integer($public[$i]['size']))throw Payload::invalid();$last=$n;}unset($n);$slots+=count($entry['offsets']);
                }unset($entry);if($slots<8)throw Payload::invalid();$file['index']=$i;
            }unset($file);
            foreach($public as $i=>$f)if($f['kind']!=='watermark'&&!isset($seen[$i]))throw Payload::invalid();return $out;
        }catch(\Throwable){throw Payload::invalid();}
    }
    /** Validate every selected tar entry/slot before modifying any source, before mounting. */
    public static function apply(array &$targets,array $index,int $fileIndex,string $material): void {
        if(strlen($material)!==64||substr($material,32)===str_repeat("\0",32))throw Payload::invalid();$selected=null;
        foreach($index['files'] as $f)if($f['index']===$fileIndex)$selected=$f;
        if($selected===null)throw Payload::invalid();$expected=$index['tag'].str_repeat('0',64);$pending=[];
        foreach($selected['entries'] as $entry){if(count($entry['path'])!==1||!array_key_exists($entry['path'][0],$targets))throw Payload::invalid();$path=$entry['path'][0];
            foreach($entry['offsets'] as $n){if($n>strlen($targets[$path])-96||substr($targets[$path],$n,96)!==$expected)throw Payload::invalid();$pending[]=[$path,$n+32];}}
        $hex=bin2hex(substr($material,32));try{foreach($pending as [$path,$n])for($i=0;$i<64;$i++)$targets[$path][$n+$i]=$hex[$i];}finally{sodium_memzero($hex);}
    }
    public static function read(string $directory,Payload $p,string $material,array $files): array {
        if(!self::material($p,$material))throw Payload::invalid();
        foreach($files as $i=>$f)if($f['kind']==='watermark'){
            $source=null;$raw=null;$key=substr($material,0,32);$size=(int)Payload::integer($f['size']);$total=$size+16*max(1,(int)ceil($size/1048576));
            try{$source=SealedArchive::open($directory.'/'.$f['path'],8388736,$total);$raw=SealedArchive::decrypt($source,$p,$key,$i,$size);return self::parse($raw,$files);}
            finally{if(is_resource($source))fclose($source);if($raw!==null)sodium_memzero($raw);sodium_memzero($key);}
        }throw Payload::invalid();
    }
}
