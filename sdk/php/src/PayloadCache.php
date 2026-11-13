<?php
declare(strict_types=1);
namespace AuthGo;

/** Content keys only: never creates, reads or deletes launcher proof files. */
final class PayloadCache
{
    public const PREFIX='AUTHGO-PAYLOAD-CACHE-v2.';
    public readonly string $identity;
    public readonly string $base;
    public function __construct(private string $directory,string $endpoint,string $appKey,private string $fingerprint,string $public)
    {
        $endpoint=preg_replace_callback('~\A(https?://)([^/?#]*)~i',fn($m)=>strtolower($m[1]).strtolower($m[2]),$endpoint);
        $this->identity=implode("\0",[$endpoint,$appKey,$fingerprint,hash('sha256',$public)]);
        $this->base='authgo-payload-v2-'.hash('sha256',$this->identity).'-';
    }
    private static function date(mixed $value): float {return $value===null?INF:(float)(new \DateTimeImmutable($value))->format('U.u');}
    /** @internal Accept only a grant already verified by Client::grant. */
    public function material(Payload $payload,mixed $grant,float $now,bool $disabled=false): array
    {
        if($disabled)throw new Error('SDK_CACHE_UNAVAILABLE');
        if(!isset($grant['issued_at'],$grant['grace_until']))throw new Error('SDK_CACHE_INVALID');
        $issued=self::date($grant['issued_at']);$grace=self::date($grant['grace_until']);
        if(($grant['is_trial']??false)||$grace<=$issued||$now>=$grace||$issued>$now+300)throw new Error('SDK_GRACE_EXPIRED');
        if(isset($grant['starts_at'])&&$now<self::date($grant['starts_at']))throw new Error('LICENSE_NOT_STARTED');
        if($now>=self::date($grant['expires_at']??null))throw new Error('LICENSE_EXPIRED');
        $seed=$grant['unlock_hash']??'';
        if(!is_string($seed)||!preg_match('/\A[0-9a-fA-F]{64}\z/D',$seed))throw new Error('SDK_CACHE_INVALID');
        $id=Payload::integer($grant['license_id']);
        if(str_starts_with($id,'-')||$id==='0'||Payload::compare($id,'18446744073709551615')>0)throw new Error('SDK_CACHE_INVALID');
        $label=$payload->cacheLabel($this->fingerprint);$hash=hash('sha256',$label,true);
        return [$this->directory.'/'.$this->base.bin2hex($hash).'.cache',Client::hkdf(hex2bin($seed),'',"authgo-unlock-v2\0".$label),
            "authgo-payload-cache-file-v{$payload->v}\0".$hash.Payload::uint64($id)];
    }
    private static function regular(array $stat): bool {return ($stat['mode']&0170000)===0100000;}
    /** @internal Require real descriptor identity and enforce POSIX 0600. */
    public static function checkedStat(mixed $stat): array
    {
        if(PHP_OS_FAMILY==='Windows'||PHP_INT_SIZE<8||!is_array($stat)||!isset($stat['dev'],$stat['ino'],$stat['mode'],$stat['size'])||
            !is_int($stat['dev'])||!is_int($stat['ino'])||!is_int($stat['mode'])||!is_int($stat['size'])||$stat['ino']===0||
            !self::regular($stat)||($stat['mode']&07777)!==0600||$stat['size']<0||$stat['size']>256)throw new Error('SDK_CACHE_UNAVAILABLE');
        return $stat;
    }
    /** @internal Compare the opened descriptor, not only pathname metadata. */
    public static function verifyHandle(string $path,mixed $handle,array $expected): array
    {
        $opened=self::checkedStat(fstat($handle));clearstatcache(true,$path);$current=self::checkedStat(@lstat($path));
        if($expected['dev']!==$opened['dev']||$expected['ino']!==$opened['ino']||$current['dev']!==$opened['dev']||$current['ino']!==$opened['ino']||$expected['size']!==$opened['size'])throw new Error('SDK_CACHE_INVALID');
        return $opened;
    }
    public function save(Payload $payload,mixed $grant,float $now,bool $disabled,string $key): void
    {
        if(!PayloadWatermark::material($payload,$key)||PHP_OS_FAMILY==='Windows'||PHP_INT_SIZE<8)return;
        $temp=null;$handle=null;$derived=null;
        try {
            [$file,$derived,$aad]=$this->material($payload,$grant,$now,$disabled);$nonce=random_bytes(12);
            $raw=self::PREFIX.Client::b64($nonce.Client::seal($derived,$nonce,$key,$aad));
            if(!is_dir($this->directory)&&!@mkdir($this->directory,0700,true)&&!is_dir($this->directory))return;
            clearstatcache(true,$file);$existing=@lstat($file);
            if($existing!==false&&!self::regular($existing))return;
            $temp=$this->directory.'/.authgo-payload-'.Client::b64(random_bytes(12)).'.tmp';
            $handle=@fopen($temp,'x+b');if($handle===false)return;
            // Verify the temp path still names our descriptor before changing its permissions.
            $opened=fstat($handle);clearstatcache(true,$temp);$path=@lstat($temp);
            if(!$opened||!$path||!self::regular($opened)||!self::regular($path)||$opened['dev']!==$path['dev']||$opened['ino']!==$path['ino'])return;
            if(!@chmod($temp,0600))return;
            $offset=0;while($offset<strlen($raw)){$n=@fwrite($handle,substr($raw,$offset));if($n===false||$n===0)return;$offset+=$n;}
            if(!@fflush($handle)||!@fsync($handle))return;
            $expected=self::checkedStat(fstat($handle));self::verifyHandle($temp,$handle,$expected);
            if(!fclose($handle))return;$handle=null;
            @rename($temp,$file);
        }catch(\Throwable){/* Best effort: an unavailable cache does not fail online unlock. */}
        finally{if(is_resource($handle))fclose($handle);if($temp!==null)@unlink($temp);if($derived!==null)sodium_memzero($derived);}
    }
    public function load(Payload $payload,mixed $grant,float $now,bool $disabled=false): string
    {
        [$file,$derived,$aad]=$this->material($payload,$grant,$now,$disabled);$handle=null;
        try {
            try {
                clearstatcache(true,$file);$before=self::checkedStat(@lstat($file));
                $handle=@fopen($file,'rb');if($handle===false)throw new Error('SDK_CACHE_UNAVAILABLE');
                $opened=self::verifyHandle($file,$handle,$before);$raw='';
                while(strlen($raw)<257&&!feof($handle)){$part=fread($handle,257-strlen($raw));if($part===false)throw new Error('SDK_CACHE_UNAVAILABLE');if($part==='')break;$raw.=$part;}
                self::verifyHandle($file,$handle,$opened);
            }catch(Error $error){throw $error;}catch(\Throwable){throw new Error('SDK_CACHE_UNAVAILABLE');}
            try {
                if(strlen($raw)>256||!str_starts_with($raw,self::PREFIX))throw new \Exception();
                $encrypted=Client::decode(substr($raw,strlen(self::PREFIX)));if(strlen($encrypted)!==92)throw new \Exception();
                $key=Client::open($derived,substr($encrypted,0,12),substr($encrypted,12),$aad);if(!PayloadWatermark::material($payload,$key)){sodium_memzero($key);throw new \Exception();}return $key;
            }catch(\Throwable){throw new Error('SDK_CACHE_INVALID','内容密钥缓存认证失败');}
        }finally{if(is_resource($handle))fclose($handle);sodium_memzero($derived);}
    }
    public function clear(bool $disabled=false): void
    {
        if($disabled)return;
        try {
            $names=@scandir($this->directory);if($names===false)return;
            foreach($names as $name)if(str_starts_with($name,$this->base)&&str_ends_with($name,'.cache'))@unlink($this->directory.'/'.$name);
        }catch(\Throwable){/* Cleanup must not mask an authenticated refusal. */}
    }
}
