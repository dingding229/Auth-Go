<?php
declare(strict_types=1);
namespace AuthGo;

/** USTAR and authenticated payload chunks. No extract(), eval(), temp streams or plaintext files. */
final class SealedArchive
{
    public const LIMIT=268435456;
    /** Bare relative includes can enter opcache even with a non-file opened_path.
     * Disable it for this request/process before exposing any protected source.
     * PHP does not allow re-enabling opcache in the same request. Fail closed if locked.
     */
    public static function disableOpcodeCache(): void
    {
        if(!extension_loaded('Zend OPcache')||in_array(strtolower((string)ini_get('opcache.enable')),['','0','off','false','no','none'],true))return;
        if(!function_exists('ini_set'))throw new Error('PAYLOAD_INVALID','内存加载器必须能够关闭本请求的 opcache');
        @ini_set('opcache.enable','0');
        if(!in_array(strtolower((string)ini_get('opcache.enable')),['','0','off','false','no','none'],true))throw new Error('PAYLOAD_INVALID','内存加载器必须能够关闭本请求的 opcache');
    }
    public static function path(string $path): string
    {
        if($path===''||strlen($path)>255||preg_match('~[\x00-\x20\x7f\\\\:%?#]~',$path)||str_starts_with($path,'/'))throw Payload::invalid();
        foreach(explode('/',$path) as $part)if($part===''||$part==='.'||$part==='..')throw Payload::invalid();
        if(preg_match('//u',$path)!==1)throw Payload::invalid();
        return $path;
    }
    private static function text(string $field): string
    {
        $end=strpos($field,"\0");
        if($end===false)return $field;
        if(trim(substr($field,$end),"\0")!=='')throw Payload::invalid();
        return substr($field,0,$end);
    }
    private static function octal(string $field,int $limit=self::LIMIT): int
    {
        if(!preg_match('/\A[0-7]+[\x00 ]*\z/D',$field))throw Payload::invalid();
        $n=octdec(rtrim($field,"\0 "));if(!is_int($n)||$n>$limit)throw Payload::invalid();return $n;
    }
    /** @internal Reject extensions, links, duplicate names, ambiguous paths and trailing data. */
    public static function unpack(string &$tar,bool $strictAliases=false): array
    {
        $files=[];$length=strlen($tar);$offset=0;$aliases=$strictAliases?new PayloadPathAliases():null;
        try {
            if($length>self::LIMIT||$length%512!==0)throw Payload::invalid();
            while($offset+1024<=$length) {
                $h=substr($tar,$offset,512);
                if($h===str_repeat("\0",512)) {
                    if(substr($tar,$offset)!==str_repeat("\0",$length-$offset)||!$files)throw Payload::invalid();
                    $names=array_keys($files);sort($names,SORT_STRING);
                    foreach($names as $name){$parts=explode('/',$name);array_pop($parts);while($parts){if(isset($files[implode('/',$parts)]))throw Payload::invalid();array_pop($parts);}}
                    return $files;
                }
                if(substr($h,257,8)!=="ustar\00000"||!in_array($h[156],["0","\0"],true)||trim(substr($h,157,100),"\0")!==''||trim(substr($h,500,12),"\0")!=='')throw Payload::invalid();
                foreach([[100,8],[108,8],[116,8],[136,12]] as [$at,$len])self::octal(substr($h,$at,$len),PHP_INT_MAX);
                foreach([329,337] as $at){$dev=substr($h,$at,8);if(trim($dev,"\0")!==''&&self::octal($dev)!==0)throw Payload::invalid();}
                $checksum=array_sum(unpack('C*',substr_replace($h,str_repeat(' ',8),148,8)));
                if(self::octal(substr($h,148,8))!==$checksum)throw Payload::invalid();
                $name=self::text(substr($h,0,100));$prefix=self::text(substr($h,345,155));
                $name=self::path(($prefix!==''?$prefix.'/':'').$name);$size=self::octal(substr($h,124,12));
                if($aliases!==null)$aliases->add($name);
                if(isset($files[$name])||count($files)>=65535)throw Payload::invalid();
                $offset+=512;$padded=(int)(ceil($size/512)*512);
                if($offset+$padded>$length||trim(substr($tar,$offset+$size,$padded-$size),"\0")!=='')throw Payload::invalid();
                if(!str_ends_with($name,'.php'))throw Payload::invalid();
                $files[$name]=substr($tar,$offset,$size);$offset+=$padded;
            }
            throw Payload::invalid();
        }catch(\Throwable $e){self::wipe($files);throw $e;}
    }
    public static function wipe(array &$files): void
    {
        foreach($files as &$bytes)if(is_string($bytes))sodium_memzero($bytes);unset($bytes);$files=[];
    }
    /** @internal Bounded regular ciphertext only; reject links and descriptor replacement. */
    public static function open(string $path,int $limit,?int $exact=null): mixed
    {
        clearstatcache(true,$path);$s=@lstat($path);
        if(!$s||($s['mode']&0170000)!==0100000||$s['size']>$limit||($exact!==null&&$s['size']!==$exact))throw Payload::invalid();
        $h=@fopen($path,'rb');if($h===false)throw Payload::invalid();
        $f=fstat($h);clearstatcache(true,$path);$after=@lstat($path);
        if(!$f||!$after||$f['dev']!==$s['dev']||$f['ino']!==$s['ino']||$after['dev']!==$f['dev']||$after['ino']!==$f['ino']||$f['size']!==$s['size']){fclose($h);throw Payload::invalid();}
        return $h;
    }
    public static function decrypt(mixed $source,Payload $payload,string $key,int $index,int $size): string
    {
        $plain='';$block=null;$count=max(1,(int)ceil($size/1048576));$binding=$payload->payloadBinding();
        try {
            if(strlen($key)!==32||$size<0||$size>self::LIMIT)throw Payload::invalid();
            for($j=0;$j<$count;$j++) {
                $n=min(1048576,$size-$j*1048576);$cipher='';
                while(strlen($cipher)<$n+16){$b=fread($source,$n+16-strlen($cipher));if($b===false||$b==='')throw Payload::invalid();$cipher.=$b;}
                $nonce=pack('N3',$index,0,$j);$aad="authgo-payload-chunk-v1\0".$binding.$nonce.chr((int)($j===$count-1));
                $block=Client::open($key,$nonce,$cipher,$aad);$plain.=$block;sodium_memzero($block);
            }
            if(fread($source,1)!=='')throw Payload::invalid();return $plain;
        }catch(\Throwable){sodium_memzero($plain);throw Payload::invalid();}
        finally{if($block!==null)sodium_memzero($block);}
    }
}

/** @internal One request/Guard owns a mount; open streams retain no private source copy. */
final class SealedMount
{
    private \WeakReference $guard;
    public readonly string $identity;
    public function __construct(Guard $guard,private array $files)
    {
        $this->guard=\WeakReference::create($guard);$this->identity='m-'.bin2hex(random_bytes(16));
    }
    public function check(): void
    {
        $guard=$this->guard->get();if(!$guard)throw new Error('SDK_NOT_ACTIVATED');$guard->sealedCheck();
    }
    public function size(string $path): int
    {
        $this->check();if(!array_key_exists($path,$this->files))throw Payload::invalid();return strlen($this->files[$path]);
    }
    public function read(string $path,int $offset,int $count): string
    {
        $this->size($path);return substr($this->files[$path],$offset,$count);
    }
    public function clear(): void {SealedArchive::wipe($this->files);}
    public function __destruct() {$this->clear();}
}

/** @internal Public solely because PHP constructs user stream wrappers by class name. */
final class SealedStream
{
    public mixed $context;
    private static array $mounts=[];
    private static ?string $probeURL=null;
    private ?SealedMount $mount=null;
    private string $path='';
    private int $offset=0;
    private int $busy=0;
    private bool $probe=false;
    private bool $revoked=false;
    private bool $revoking=false;
    public static function install(Guard $guard,string $name,array $files): SealedMount
    {
        if(isset(self::$mounts[$name])&&self::$mounts[$name]->get()!==null)throw Payload::invalid();
        if(!in_array('authgo-sealed',stream_get_wrappers(),true)) {
            if(!stream_wrapper_register('authgo-sealed',self::class))throw Payload::invalid();
        } elseif(!self::ownsWrapper())throw Payload::invalid(); // Inspect the current wrapper, not historical registration.
        $mount=new SealedMount($guard,$files);$ref=\WeakReference::create($mount);
        self::$mounts[$name]=$ref;self::$mounts[$mount->identity]=$ref;return $mount;
    }
    /** PHP exposes scheme names, not their implementing class. Probe without source
     * bytes and verify the native resource's wrapper_data before adopting a scheme.
     * Independent of mount count, and detects replacement after our last close.
     */
    private static function ownsWrapper(): bool
    {
        $handle=null;self::$probeURL='authgo-sealed://_authgo_probe/'.bin2hex(random_bytes(16));
        try {
            $handle=@fopen(self::$probeURL,'rb');if(!is_resource($handle))return false;
            $wrapper=stream_get_meta_data($handle)['wrapper_data']??null;
            return $wrapper instanceof self&&$wrapper->probe;
        }catch(\Throwable){return false;}
        finally{self::$probeURL=null;if(is_resource($handle))fclose($handle);}
    }
    public static function remove(SealedMount $mount): void
    {
        $mount->clear();
        // PHP may prefetch 8 KiB for fread(1). Close our idle native streams too,
        // otherwise their engine buffer could survive revocation of the source table.
        // Never close the stream whose callback is currently on the engine stack.
        foreach(get_resources('stream') as $handle) {
            $wrapper=stream_get_meta_data($handle)['wrapper_data']??null;
            if(!($wrapper instanceof self)||$wrapper->mount!==$mount)continue;
            $wrapper->revoked=true;
            if(!$wrapper->busy){fclose($handle);continue;}
            // Do not free a native stream from inside its callback. SEEK_END is
            // never a buffer-only seek: it invalidates PHP's readpos/writepos.
            // Our private revoking branch bypasses Guard only for that empty seek.
            $wrapper->revoking=true;
            try{fseek($handle,0,SEEK_END);}finally{$wrapper->revoking=false;}
        }
        foreach(self::$mounts as $key=>$ref)if($ref->get()===null||$ref->get()===$mount)unset(self::$mounts[$key]);
        // Keep our wrapper registered, but never accept an unowned replacement.
    }
    private static function resolve(string $url): array
    {
        if(!preg_match('~\Aauthgo-sealed://([a-z0-9_-]+)/(.+)\z~Ds',$url,$m))throw Payload::invalid();
        $mount=(self::$mounts[$m[1]]??null)?->get();if(!$mount)throw new Error('SDK_NOT_ACTIVATED');
        $parts=[];
        foreach(explode('/',$m[2]) as $part) {
            if($part==='.')continue;
            if($part==='..'){if(!$parts)throw Payload::invalid();array_pop($parts);continue;}
            SealedArchive::path($part);$parts[]=$part;
        }
        $path=SealedArchive::path(implode('/',$parts));$mount->size($path);return[$mount,$path];
    }
    public function stream_open(string $path,string $mode,int $options,?string &$opened_path): bool
    {
        if($mode!=='r'&&$mode!=='rb')return false;
        if(self::$probeURL!==null&&hash_equals(self::$probeURL,$path)){$this->probe=true;$opened_path=$path;return true;}
        [$this->mount,$this->path]=self::resolve($path);$this->offset=0;
        // Fresh canonical identity prevents cross-request/version require_once/opcache aliases.
        $opened_path='authgo-sealed://'.$this->mount->identity.'/'.$this->path;return true;
    }
    private function checked(callable $action): mixed
    {
        if($this->revoked||$this->mount===null)throw new Error('SDK_NOT_ACTIVATED');
        $this->busy++;try{return $action();}finally{$this->busy--;}
    }
    public function stream_read(int $count): string
    {
        if($this->probe)return '';
        return $this->checked(function()use($count): string {$data=$this->mount->read($this->path,$this->offset,$count);$this->offset+=strlen($data);return $data;});
    }
    public function stream_eof(): bool {if($this->probe)return true;return $this->checked(fn(): bool=>$this->offset>=$this->mount->size($this->path));}
    public function stream_tell(): int {return $this->offset;}
    public function stream_seek(int $offset,int $whence=SEEK_SET): bool
    {
        if($this->revoking&&$offset===0&&$whence===SEEK_END){$this->offset=0;return true;}
        $size=$this->checked(fn(): int=>$this->mount->size($this->path));$next=match($whence){SEEK_SET=>$offset,SEEK_CUR=>$this->offset+$offset,SEEK_END=>$size+$offset,default=>-1};
        if($next<0||$next>$size)return false;$this->offset=$next;return true;
    }
    private static function stat(int $size): array {return ['dev'=>0,'ino'=>0,'mode'=>0100400,'nlink'=>1,'uid'=>0,'gid'=>0,'rdev'=>0,'size'=>$size,'atime'=>0,'mtime'=>0,'ctime'=>0,'blksize'=>-1,'blocks'=>-1];}
    public function stream_stat(): array {if($this->probe)return self::stat(0);return $this->checked(fn(): array=>self::stat($this->mount->size($this->path)));}
    public function url_stat(string $path,int $flags): array|false
    {
        try{[$mount,$file]=self::resolve($path);return self::stat($mount->size($file));}catch(Error){return false;}
    }
    public function stream_set_option(int $option,int $arg1,int $arg2): bool {return false;}
    public function stream_close(): void {$this->mount=null;}
}
