<?php
declare(strict_types=1);
namespace AuthGo;

/** Original payload.json. Public config binds the envelope; it never chooses a connection target. */
final class Payload
{
    private const FIELDS = ['v','app_key','version','built_at','key_id','config','manifest','envelope'];
    public function __construct(
        public readonly int $v,
        public readonly string $appKey,
        public readonly string $version,
        public readonly string $builtAt,
        public readonly string $keyId,
        public readonly string $config,
        public readonly string $manifest,
        public readonly string $e,
        public readonly string $n,
        public readonly string $c,
    ) {}
    public static function invalid(): Error { return new Error('PAYLOAD_INVALID', '加密载荷无效'); }
    /** @internal Strict schema, including null-valued required keys. */
    public static function object(mixed $value, array $required, array $optional=[]): \ArrayObject
    {
        if (!$value instanceof \ArrayObject) throw self::invalid();
        $keys=array_keys($value->getArrayCopy());
        if (array_diff($required,$keys) || array_diff($keys,array_merge($required,$optional))) throw self::invalid();
        return $value;
    }
    public static function text(mixed $value): string
    {
        if (!is_string($value) || preg_match('//u',$value)!==1) throw self::invalid();
        return $value;
    }
    /** @internal Exact JSON integer; quoted numbers, exponent and decimal spellings are not integers. */
    public static function integer(mixed $value): string
    {
        $raw=$value instanceof JsonNumber?$value->raw:(is_int($value)?(string)$value:null);
        if ($raw===null || !preg_match('/\A-?(0|[1-9][0-9]*)\z/D',$raw)) throw self::invalid();
        return $raw==='-0'?'0':$raw;
    }
    /** @internal Compare normalized nonnegative decimal strings without float conversion. */
    public static function compare(string $a,string $b): int
    {
        if (!preg_match('/\A(0|[1-9][0-9]*)\z/D',$a) || !preg_match('/\A(0|[1-9][0-9]*)\z/D',$b)) throw self::invalid();
        return strlen($a)<=>strlen($b) ?: strcmp($a,$b);
    }
    /** @internal uint64 big endian, including values above PHP_INT_MAX, without GMP. */
    public static function uint64(string $decimal): string
    {
        if (self::compare($decimal,'18446744073709551615')>0) throw self::invalid();
        $out='';
        for ($i=0;$i<8;$i++) {
            $quotient='';$carry=0;
            foreach (str_split($decimal) as $digit) {
                $carry=$carry*10+(ord($digit)-48);$next=intdiv($carry,256);$carry%=256;
                if ($quotient!=='' || $next!==0) $quotient.=(string)$next;
            }
            $decimal=$quotient===''?'0':$quotient;$out=chr($carry).$out;
        }
        if ($decimal!=='0') throw self::invalid();
        return $out;
    }
    public static function lp(string ...$values): string
    {
        $out='';foreach($values as $value)$out.=pack('N',strlen($value)).$value;return $out;
    }
    /** @internal Match Go net/url.Parse HTTPS predicate, never parse_url normalization. */
    public static function https(string $value): void
    {
        self::text($value);
        if (preg_match('/[\x00-\x1f\x7f]/',$value) || !preg_match('~\A(?i:https)://([^/?#]*)([^?#]*)(?:\?([^#]*))?(?:#(.*))?\z~Ds',$value,$m)) throw self::invalid();
        $host=$m[1];$path=$m[2];
        if ($host==='' || str_contains($host,'@') || ($m[3]??'')!=='' || ($m[4]??'')!=='') throw self::invalid();
        if (str_contains($host,'[') && !str_starts_with($host,'[')) throw self::invalid();
        if (str_starts_with($host,'[')) {
            $end=strrpos($host,']');
            if ($end===false || $end<=1 || !preg_match('/\A(:[0-9]*)?\z/D',substr($host,$end+1))) throw self::invalid();
        } elseif (str_contains($host,':')) {
            $end=strrpos($host,':');if ($end===0 || !preg_match('/\A[0-9]*\z/D',substr($host,$end+1))) throw self::invalid();
        }
        foreach(str_split($host) as $char) {
            $code=ord($char);
            if($code<128 && !(($code>=65&&$code<=90)||($code>=97&&$code<=122)||($code>=48&&$code<=57)||str_contains("_.~!$&'()*+,;=:[]<>\"%-",$char)))throw self::invalid();
        }
        if(preg_match('/%(?![0-9a-fA-F]{2})/',$host.$path))throw self::invalid();
        preg_match_all('/%([0-9a-fA-F]{2})/',$host,$escaped);
        foreach($escaped[1] as $hex){$code=hexdec($hex);if($code<128&&$code!==37)throw self::invalid();}
    }
    private static function validConfig(string $value,string $appKey): void
    {
        if(strlen($value)>32768 || !str_starts_with($value,'authgo2.'))throw self::invalid();
        $c=self::object(Json::parse(Client::decode(substr($value,8))),['url','app_key','app_secret','public_key','gateway_key'],[]);
        foreach(['url','app_key','app_secret','public_key','gateway_key'] as $key)self::text($c[$key]);
        if($c['app_key']!==$appKey || $c['app_secret']==='')throw self::invalid();
        self::https($c['url']);
        $public=base64_decode($c['public_key'],true);
        if($public===false || strlen($public)!==32 || base64_encode($public)!==$c['public_key'] || strlen(Client::decode($c['gateway_key']))!==32)throw self::invalid();
    }
    private static function validManifest(string $value,int $version=2): string
    {
        $raw=Client::decode($value);if(strlen($raw)>(8<<20))throw self::invalid();
        $m=self::object(Json::parse($raw),['files']);$files=$m['files'];
        if(!is_array($files)||count($files)<1||count($files)>65535)throw self::invalid();
        $names=[];$metadata=0;
        foreach($files as $i=>$item) {
            $f=self::object($item,['name','kind','path','size','chunk_size','encoding'],['python_version','main_class','architecture']);
            foreach($f as $key=>$field)if(!in_array($key,['size','chunk_size'],true))self::text($field);
            $name=$f['name'];$size=self::integer($f['size']);
            if(!preg_match('/\A[a-z0-9_-]+\z/D',$name)||strlen($name)>128||isset($names[$name])||$f['path']!==sprintf('%08d.agc',$i)||
                str_starts_with($size,'-')||self::compare($size,'4611686018427387903')>0||self::integer($f['chunk_size'])!=='1048576')throw self::invalid();
            $names[$name]=true;$kind=$f['kind'];
            if($kind==='watermark') {
                if($version!==2||$name!=='__authgo_watermark'||$f['encoding']!=='raw'||$size==='0'||self::compare($size,'8388608')>0||count($f)!==6)throw self::invalid();
                $metadata++;continue;
            }
            if($version===2&&$name==='__authgo_watermark')throw self::invalid();
            $encoding=match($kind){'python','php','dotnet'=>'tar','node','java','protect'=>'raw',default=>''};
            if($encoding===''||$f['encoding']!==$encoding||$kind==='python'&&($f['python_version']??'')===''||$kind==='protect'&&!in_array($f['architecture']??'',['amd64','arm64'],true))throw self::invalid();
        }
        if($version===2&&($metadata!==1||count($files)<2))throw self::invalid();
        return $raw;
    }
    /** @internal Envelope base AAD, before the envelope's ephemeral public key. */
    public function aad(): string
    {
        if($this->v!==2)throw self::invalid();
        foreach([$this->appKey,$this->version,$this->builtAt,$this->keyId,$this->config,$this->manifest] as $s)self::text($s);
        if($this->appKey===''||strlen($this->appKey)>256||strlen($this->keyId)>128||!preg_match('/\A[a-z0-9_-]+\z/D',$this->keyId)||strlen($this->version)>256||
            !preg_match('/\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-([0-9A-Za-z-]+)(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?\z/D',$this->version))throw self::invalid();
        $core=explode('+',$this->version,2)[0];$parts=explode('-',$core,2);
        if(isset($parts[1]))foreach(explode('.',$parts[1]) as $part)if(preg_match('/\A0[0-9]+\z/D',$part))throw self::invalid();
        if(!preg_match('/\A([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z\z/D',$this->builtAt,$t))throw self::invalid();
        [$year,$month,$day,$hour,$minute,$second]=array_map('intval',array_slice($t,1));
        $leap=$year%4===0&&($year%100!==0||$year%400===0);$days=[31,$leap?29:28,31,30,31,30,31,31,30,31,30,31];
        if($month<1||$month>12||$day<1||$day>$days[$month-1]||$hour>23||$minute>59||$second>59)throw self::invalid();
        self::validConfig($this->config,$this->appKey);
        return "authgo-payload-envelope-v{$this->v}\0".self::lp($this->appKey,$this->version,$this->builtAt,$this->keyId,$this->config).hash('sha256',self::validManifest($this->manifest,$this->v),true);
    }
    public function payloadBinding(): string
    {
        try {
            $aad=$this->aad();$e=Client::decode($this->e);$n=Client::decode($this->n);$c=Client::decode($this->c);
            if(strlen($e)!==32||strlen($n)!==12||strlen($c)!==48)throw self::invalid();
            return hash('sha256',$aad.$e.$n.$c,true);
        }catch(\Throwable){throw self::invalid();}
    }
    public function toObject(): \ArrayObject
    {
        return new \ArrayObject(['v'=>$this->v,'app_key'=>$this->appKey,'version'=>$this->version,'built_at'=>$this->builtAt,'key_id'=>$this->keyId,'config'=>$this->config,'manifest'=>$this->manifest,
            'envelope'=>new \ArrayObject(['e'=>$this->e,'n'=>$this->n,'c'=>$this->c])]);
    }
    public static function parsePayload(string $raw): self
    {
        try {
            if(strlen($raw)>65536)throw self::invalid();
            $p=self::object(Json::parse($raw),self::FIELDS);$version=self::integer($p['v']);if($version!=='2')throw self::invalid();
            $e=self::object($p['envelope'],['e','n','c']);
            $out=new self((int)$version,self::text($p['app_key']),self::text($p['version']),self::text($p['built_at']),self::text($p['key_id']),self::text($p['config']),self::text($p['manifest']),self::text($e['e']),self::text($e['n']),self::text($e['c']));
            $out->payloadBinding();return $out;
        }catch(\Throwable){throw self::invalid();}
    }
    /** @internal */
    public function validated(): self {try{return self::parsePayload(Json::encode($this->toObject()));}catch(\Throwable){throw self::invalid();}}
    public function rewrapAAD(string $ephemeral,string $challenge): string
    {
        if(strlen($ephemeral)!==32||strlen($challenge)!==32)throw self::invalid();
        return "authgo-payload-rewrap-v{$this->v}\0".self::lp($this->appKey,$this->version,$this->builtAt,$this->keyId).hash('sha256',Client::decode($this->manifest),true).$ephemeral.$challenge;
    }
    public function cacheLabel(string $fingerprint): string
    {
        return "authgo-payload-cache-v{$this->v}\0".self::lp($this->appKey,$fingerprint,$this->keyId,$this->version).hash('sha256',Client::decode($this->manifest),true).$this->payloadBinding();
    }
    public function unwrap(array $wrapped,string $private,string $challenge): string
    {
        $shared=null;$kek=null;
        try {
            $e=Client::decode($wrapped['e']);$n=Client::decode($wrapped['n']);$c=Client::decode($wrapped['c']);
            if(strlen($e)!==32||strlen($n)!==12||strlen($c)!==48)throw new \Exception();
            $shared=sodium_crypto_scalarmult($private,$e);$aad=$this->rewrapAAD(sodium_crypto_scalarmult_base($private),$challenge);
            $kek=Client::hkdf($shared,hash('sha256',$aad,true),'authgo/payload/v1/rewrap');$key=Client::open($kek,$n,$c,$aad);
            if(strlen($key)!==32)throw new \Exception();return $key;
        }catch(\Throwable){throw new Error('SDK_RESPONSE_INVALID','内容密钥响应认证失败');}
        finally{if($shared!==null)sodium_memzero($shared);if($kek!==null)sodium_memzero($kek);}
    }
}
