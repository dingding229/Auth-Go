<?php
declare(strict_types=1);
require_once __DIR__.'/../src/Client.php';
use AuthGo\Client;
use AuthGo\Json;
use AuthGo\JsonNumber;
use AuthGo\Error;
use AuthGo\Result;
use AuthGo\Payload;
use AuthGo\PayloadCache;

/** The transport seam performs actual v2 AEAD, HMAC, Ed25519 and content-key rewrap. */
final class PayloadTestServer
{
    public string $signer,$gateway,$key,$seed,$mode='',$code='';
    public Payload $payload;
    public \ArrayObject $config;
    public array $calls=[],$changes=[],$grantChanges=[];
    public int $now,$grace=120;
    public mixed $id=42;
    public bool $trial=false,$floating=false;
    public ?string $expires=null;
    public function __construct(string $context)
    {
        $v=PayloadTests::vector('payload-cache-v2.json');$this->payload=Payload::parsePayload(Json::encode($v['payload']));
        $this->now=(int)$v['proof_now']->raw;$this->key=hex2bin($v['content_key_hex']);$this->seed=str_repeat("\x27",32);
        $this->signer=sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(hash('sha256','public-synthetic-sign:'.$context,true)));
        $this->gateway=hash('sha256','public-synthetic-gateway:'.$context,true);
        $this->config=Json::parse(Client::decode(substr($this->payload->config,8)));
        $this->config['public_key']=base64_encode(sodium_crypto_sign_publickey_from_secretkey($this->signer));
        $this->config['gateway_key']=Client::b64(sodium_crypto_scalarmult_base($this->gateway));$this->config['url']='https://PAYLOAD.EXAMPLE.TEST';
    }
    public function client(string $directory,string $fp=PayloadTests::FP): Client
    {
        return new Client('authgo2.'.Client::b64(Json::encode($this->config)),['cache_dir'=>$directory,'fingerprint'=>$fp,'clock'=>fn()=>$this->now,'transport'=>$this->transport(...)]);
    }
    public function signed(mixed $grant): string
    {
        $raw=Json::encode($grant);return Client::b64($raw).'.'.Client::b64(sodium_crypto_sign_detached("authgo-ticket-v2\0".$raw,$this->signer));
    }
    private function ticket(mixed $body): \ArrayObject
    {
        return new \ArrayObject(['v'=>2,'app_key'=>$this->config['app_key'],'challenge'=>$body['challenge'],'license_id'=>$this->id,
            'license_ref'=>'public-synthetic-ref','device_hash'=>Client::hash($body['device_fingerprint']),'status'=>'active','issued_at'=>PayloadTests::iso($this->now),
            'starts_at'=>null,'expires_at'=>$this->expires,'features'=>new \ArrayObject(['export'=>true]),'next_check_in'=>10,'grace_until'=>PayloadTests::iso($this->now+$this->grace),
            'lease_expires_at'=>$this->floating?PayloadTests::iso($this->now+20):null,'floating'=>$this->floating,'is_trial'=>$this->trial,'unlock_hash'=>Client::hash($this->seed)]);
    }
    public function transport(string $url,string $packet,array $headers,float $timeout,int $limit): array
    {
        PayloadTests::equal($url,'https://PAYLOAD.EXAMPLE.TEST/api/v1/client/gateway');PayloadTests::equal($headers,['Content-Type'=>'application/json']);PayloadTests::equal($timeout,10.0);PayloadTests::equal($limit,2097152);
        $this->calls[]='transport';if($this->mode==='network')throw new Error('SDK_NETWORK_ERROR');
        if(in_array($this->mode,['status','html'],true))return[$this->mode==='status'?502:200,[],'<html>not signed</html>'];
        $outer=Json::parse($packet);$aad="authgo-gateway-v2\0".$outer['k']."\0".$outer['e'];$salt=hash('sha256',$aad,true);
        $shared=sodium_crypto_scalarmult($this->gateway,Client::decode($outer['e']));
        $inner=Json::parse(Client::unpad(Client::open(Client::hkdf($shared,$salt,'authgo/v2/request'),Client::decode($outer['n']),Client::decode($outer['c']),$aad)));
        $body=$inner['body'];$op=$inner['op'];$nonce=$inner['nonce'];
        PayloadTests::equal($inner['signature'],hash_hmac('sha256',$op.$inner['timestamp'].$nonce.Client::hash(Json::encode($body)),$this->config['app_secret']));
        PayloadTests::equal(strlen(Client::decode($body['challenge'])),32);$this->calls[array_key_last($this->calls)]=$op;
        $grant=$this->ticket($body);$data=clone $grant;$data['unlock_seed']=Client::b64($this->seed);$data['request_nonce']=$nonce;$data['heartbeat_interval']=5;$data['satisfied_methods']=$this->floating?['KEY','FLOATING']:['KEY'];
        if($op==='activate')$data['activation_token']='act_'.Client::b64(str_repeat("\x42",32));
        if($op==='deactivate')$data['deactivated']=true;
        if($op==='release-seat')$data['released']=true;
        if($op==='payload.unlock') {
            $keys=array_keys($body->getArrayCopy());sort($keys);$expected=['license_key','activation_token','device_fingerprint','payload','ephemeral_public_key','challenge'];
            if(\AuthGo\isPersistentRuntime())$expected[]='instance_session';sort($expected);PayloadTests::equal($keys,$expected);
            PayloadTests::equal($body['license_key'],PayloadTests::LICENSE);PayloadTests::check(str_starts_with($body['activation_token'],'act_'));
            PayloadTests::equal(Payload::parsePayload(Json::encode($body['payload']))->payloadBinding(),$this->payload->payloadBinding());
            $private=random_bytes(32);$ephemeral=Client::decode($body['ephemeral_public_key']);$wrapAAD=$this->payload->rewrapAAD($ephemeral,Client::decode($body['challenge']));
            $kek=Client::hkdf(sodium_crypto_scalarmult($private,$ephemeral),hash('sha256',$wrapAAD,true),'authgo/payload/v1/rewrap');$n=random_bytes(12);
            if($this->payload->v===2)$data['watermark']=str_repeat('19',32);
            $data['e']=Client::b64(sodium_crypto_scalarmult_base($private));$data['n']=Client::b64($n);$data['c']=Client::b64(Client::seal($kek,$n,$this->key,$wrapAAD));sodium_memzero($private);sodium_memzero($kek);
            switch($this->mode) {
                case 'challenge':$grant['challenge']=Client::b64(str_repeat("\x01",32));break;
                case 'license':$grant['license_id']=41;$data['license_id']=41;break;
                case 'seed':$data['unlock_seed']=Client::b64(str_repeat("\x01",32));break;
                case 'issued':$grant['issued_at']=PayloadTests::iso($this->now+301);$grant['grace_until']=PayloadTests::iso($this->now+500);break;
                case 'wrap':$data['c']=Client::b64(str_repeat("\x01",48));break;
                case 'missing-wrap':unset($data['e']);break;
                case 'trial':$grant['is_trial']=true;break;
                case 'zero':$grant['grace_until']=$grant['issued_at'];break;
            }
        }
        foreach($this->grantChanges as $key=>$value)$grant[$key]=$value;$data['ticket']=$this->signed($grant);
        foreach($this->changes as $key=>$value)$data[$key]=$value;
        $env=['code'=>$this->code===''?'OK':$this->code,'data'=>$data,'ts'=>$this->now,'nonce'=>$nonce];
        $env['signature']=base64_encode(sodium_crypto_sign_detached(Json::encode(['code'=>$env['code'],'data'=>$data,'ts'=>$this->now]),$this->signer));
        if($this->mode==='signature')$env['signature']=base64_encode(str_repeat("\x01",64));
        if($this->mode==='watermark-tamper'&&$op==='payload.unlock'){
            // Keep the signature; replace only the valid watermark before encryption.
            $data['watermark']=str_repeat('2a',32);
        }
        if($this->mode==='nonce')$env['nonce']='wrong';
        $n=random_bytes(12);$context=$aad."\0".Client::hash($outer['n'].'.'.$outer['c']);
        return[200,[],Json::encode(['n'=>Client::b64($n),'c'=>Client::b64(Client::seal(Client::hkdf($shared,$salt,'authgo/v2/response'),$n,Client::pad(Json::encode($env)),$context))])];
    }
}
final class PayloadTestFixture
{
    public string $dir;public PayloadTestServer $server;public Client $client;public Payload $payload;public Result $result;
    public function __construct(?string $directory=null)
    {
        $this->dir=$directory??sys_get_temp_dir().'/authgo-payload-'.bin2hex(random_bytes(12));if(!is_dir($this->dir))mkdir($this->dir,0700,true);
        $this->server=new PayloadTestServer($this->dir);$this->client=$this->server->client($this->dir);$this->payload=$this->server->payload;
    }
    public function prime(): self {$this->result=$this->client->check(PayloadTests::LICENSE);PayloadTests::equal($this->client->unlockPayload($this->payload),$this->server->key);return $this;}
    public function caches(): array {return glob($this->dir.'/authgo-payload-v2-*.cache')?:[];}
    public function clean(): void
    {
        foreach(new \FilesystemIterator($this->dir,\FilesystemIterator::SKIP_DOTS) as $file){if($file->isDir()&&!$file->isLink()){foreach(new \FilesystemIterator($file->getPathname()) as $child)@unlink($child->getPathname());@rmdir($file->getPathname());}else @unlink($file->getPathname());}@rmdir($this->dir);
    }
}
final class PayloadTests
{
    public const LICENSE='AUTH-RNMSQ-VSQQA-4S4NH-JDGCM';
    public const FP='c4ffc8a324a624018c71f7b23e99eafda2093769f82cddba01a2f1fb32d18bcd';
    private static int $cases=0;
    public static function check(bool $ok): void {if(!$ok)throw new \RuntimeException('payload assertion failed');}
    public static function equal(mixed $actual,mixed $expected): void {if($actual!==$expected)throw new \RuntimeException('payload value mismatch');}
    public static function error(string $code,callable $action): void {try{$action();throw new \RuntimeException('expected '.$code);}catch(Error $e){self::equal($e->errorCode,$code);}}
    public static function vector(string $file): mixed {return Json::parse(file_get_contents(__DIR__.'/../../vectors/'.$file));}
    public static function iso(int $now): string {return gmdate('Y-m-d\TH:i:s\Z',$now);}
    private static function case(string $name,callable $action): void {$action();self::$cases++;echo 'payload: '.$name." PASS\n";}
    private static function fixture(callable $action,bool $prime=true): void {$f=new PayloadTestFixture();try{if($prime)$f->prime();$action($f);}finally{$f->clean();}}
    private static function result(PayloadTestFixture $f,mixed $g): Result {return new Result($f->client,$g,$f->server->signed($g));}
    private static function property(object $object,string $name): mixed {$p=new \ReflectionProperty($object,$name);$p->setAccessible(true);return $p->getValue($object);}
    private static function vectors(): void
    {
        $v=self::vector('payload-unlock-v2.json');$p=Payload::parsePayload(Json::encode($v['payload']));$private=hex2bin($v['client_private_hex']);$ephemeral=sodium_crypto_scalarmult_base($private);$challenge=hex2bin($v['challenge_hex']);
        self::equal(bin2hex($ephemeral),$v['client_public_hex']);$aad=$p->rewrapAAD($ephemeral,$challenge);self::equal(bin2hex($aad),$v['rewrap_aad_hex']);
        $shared=sodium_crypto_scalarmult($private,hex2bin($v['server_public_hex']));self::equal(bin2hex($shared),$v['shared_hex']);self::equal(hash('sha256',$aad),$v['salt_hex']);
        self::equal(bin2hex(Client::hkdf($shared,hash('sha256',$aad,true),'authgo/payload/v1/rewrap')),$v['kek_hex']);
        self::equal($p->unwrap($v['response']->getArrayCopy(),$private,$challenge),hex2bin($v['content_key_hex']));
        $o=self::vector('payload-envelope.json');$op=Payload::parsePayload(Json::encode($o['payload']));self::equal(bin2hex($op->payloadBinding()),$o['binding_hex']);
        $envelope=$op->aad().Client::decode($op->e);self::equal(bin2hex($envelope),$o['envelope_aad_hex']);
        $secret=sodium_crypto_scalarmult(hex2bin($o['recipient_private_hex']),Client::decode($op->e));self::equal(bin2hex($secret),$o['shared_hex']);self::equal(hash('sha256',$envelope),$o['salt_hex']);
        $kek=Client::hkdf($secret,hash('sha256',$envelope,true),'authgo/payload/v1/wrap');self::equal(bin2hex($kek),$o['kek_hex']);self::equal(Client::open($kek,Client::decode($op->n),Client::decode($op->c),$envelope),hex2bin($o['content_key_hex']));
        $c=self::vector('payload-cache-v2.json');$cp=Payload::parsePayload(Json::encode($c['payload']));$label=$cp->cacheLabel($c['fingerprint']);self::equal(bin2hex($label),$c['label_hex']);
        $info="authgo-unlock-v2\0".$label;self::equal(bin2hex($info),$c['resource_info_hex']);$key=Client::hkdf(hex2bin($c['unlock_hash_hex']),'',$info);self::equal(bin2hex($key),$c['cache_key_hex']);
        $fileAAD="authgo-payload-cache-file-v2\0".hash('sha256',$label,true).Payload::uint64($c['license_id']->raw);self::equal(bin2hex($fileAAD),$c['aad_hex']);
        $cipher=Client::seal($key,hex2bin($c['nonce_hex']),hex2bin($c['material_hex']),$fileAAD);self::equal(bin2hex($cipher),$c['ciphertext_hex']);self::equal(PayloadCache::PREFIX.Client::b64(hex2bin($c['nonce_hex']).$cipher),$c['file_utf8']);
        self::equal(bin2hex(Payload::uint64('18446744073709551615')),'ffffffffffffffff');self::equal(bin2hex(Payload::uint64('9223372036854775808')),'8000000000000000');
        self::fixture(function($f)use($c,$cp,$key,$fileAAD){
            $client=new Client($cp->config,['fingerprint'=>$c['fingerprint'],'cache_dir'=>$f->dir,'clock'=>fn()=>(float)$c['proof_now']->raw]);$cache=self::property($client,'payloadCache');
            self::equal($cache->identity,$c['cache_identity_utf8']);$spelling=new PayloadCache($f->dir,'HTTPS://EXAMPLE.TEST/Keep%2FPath?Case=YES','app',self::FP,str_repeat("\0",32));self::check(str_starts_with($spelling->identity,"https://example.test/Keep%2FPath?Case=YES\0app\0"));
            $g=Json::parse(Client::decode(explode('.',$c['ticket'])[0]));$result=new Result($client,$g,$c['ticket']);[$file,$derived,$aad]=$cache->material($cp,$g,(float)$c['proof_now']->raw);
            self::equal(basename($file),$c['filename']);self::equal($derived,$key);self::equal($aad,$fileAAD);file_put_contents($file,$c['file_utf8']);chmod($file,0600);
            self::equal($client->loadPayloadKey($cp,$result),hex2bin($c['material_hex']));$client->savePayloadKey($cp,$result,hex2bin($c['material_hex']));self::equal($client->loadPayloadKey($cp,$result),hex2bin($c['material_hex']));
            clearstatcache(true,$file);self::equal(fileperms($file)&07777,0600);self::check(!(glob($f->dir.'/*proof*')?:[]));
        },false);
        echo '{"language":"php","payload_vectors":"PASS","vectors":["payload-envelope","payload-unlock-v2","payload-cache-v2"]}'.PHP_EOL;
    }
    public static function v2(): Payload { return Payload::parsePayload(Json::encode(self::vector('payload-cache-v2.json')['payload'])); }
    private static function watermarkSignatureTamperV2(): void
    {
        $p=self::v2();$f=new PayloadTestFixture();$f->server->payload=$f->payload=$p;
        try {
            $f->client->check(self::LICENSE);self::equal(glob($f->dir.'/authgo-payload-v*-*.cache'),[]);
            $before=count($f->server->calls);$f->server->mode='watermark-tamper';
            self::error('SDK_RESPONSE_SIGNATURE_INVALID',fn()=>$f->client->unlockPayloadMaterial($p));
            self::equal(glob($f->dir.'/authgo-payload-v*-*.cache'),[]);
            self::error('SDK_RESPONSE_SIGNATURE_INVALID',fn()=>$f->client->unlockPayload($p));
            self::equal(glob($f->dir.'/authgo-payload-v*-*.cache'),[]);
            self::equal(array_slice($f->server->calls,$before),['payload.unlock','payload.unlock']);
            $f->server->mode='';self::equal($f->client->unlockPayloadMaterial($p),$f->server->key.str_repeat("\x19",32));
        }finally{$f->clean();}
    }

    private static function watermarkV2(): void
    {
        $p=self::v2();self::equal(Payload::parsePayload(Json::encode($p->toObject()))->payloadBinding(),$p->payloadBinding());self::check(str_starts_with($p->aad(),"authgo-payload-envelope-v2\0"));
        self::error('PAYLOAD_INVALID',fn()=>(new Payload(99,$p->appKey,$p->version,$p->builtAt,$p->keyId,$p->config,$p->manifest,$p->e,$p->n,$p->c))->validated());
        $m=Json::parse(Client::decode($p->manifest));$files=$m['files'];$files[count($files)-1]['main_class']='';$m['files']=$files;
        self::error('PAYLOAD_INVALID',fn()=>(new Payload(2,$p->appKey,$p->version,$p->builtAt,$p->keyId,$p->config,Client::b64(Json::encode($m)),$p->e,$p->n,$p->c))->validated());
        foreach([str_repeat('0',64),str_repeat('A',64),'1',32,null] as $bad)self::error('SDK_RESPONSE_INVALID',fn()=>\AuthGo\PayloadWatermark::response($bad));
        $f=new PayloadTestFixture();$f->server->payload=$f->payload=$p;
        try {
            $f->result=$f->client->check(self::LICENSE);self::equal($f->client->unlockPayload($p),$f->server->key);$material=$f->client->unlockPayloadMaterial($p);
            self::equal($material,$f->server->key.str_repeat("\x19",32));self::equal($f->client->loadPayloadKey($p,$f->result),$material);self::check(count(glob($f->dir.'/authgo-payload-v2-*'))===1);
            $grant=Json::parse(Client::decode(explode('.',$f->result->ticket())[0]));$cache=self::property($f->client,'payloadCache');
            $other=Json::parse(Json::encode($grant));$other['license_id']=43;self::error('SDK_CACHE_INVALID',fn()=>$cache->load($p,$other,$f->server->now));
            [$file,$derived,$aad]=$cache->material($p,$grant,$f->server->now);$saved=file_get_contents($file);$nonce=random_bytes(12);
            file_put_contents($file,'AUTHGO-PAYLOAD-CACHE-v2.'.Client::b64($nonce.Client::seal($derived,$nonce,$f->server->key,$aad)));self::error('SDK_CACHE_INVALID',fn()=>$cache->load($p,$grant,$f->server->now));file_put_contents($file,$saved);sodium_memzero($derived);
            $f->server->changes['watermark']=str_repeat('0',64);self::error('SDK_RESPONSE_INVALID',fn()=>$f->client->unlockPayloadMaterial($p));$f->server->changes=[];
            $f->server->mode='network';self::equal($f->client->unlockPayloadMaterial($p),$material);$f->server->now+=121;self::error('SDK_NETWORK_ERROR',fn()=>$f->client->unlockPayloadMaterial($p));$f->server->now-=121;
            $f->server->mode='';$f->server->code='LICENSE_REVOKED';self::error('LICENSE_REVOKED',fn()=>$f->client->unlockPayloadMaterial($p));self::equal(glob($f->dir.'/authgo-payload-v2-*'),[]);
            self::equal(count($f->caches()),0);
            $f->server->code='';$f->client->check(self::LICENSE);$f->server->trial=true;$f->client->unlockPayloadMaterial($p);self::equal(glob($f->dir.'/authgo-payload-v2-*'),[]);sodium_memzero($material);
        }finally{$f->clean();}
        $tag=str_repeat('a',32);$target=str_repeat($tag.str_repeat('0',64),8);$files=[new \ArrayObject(['kind'=>'php','size'=>strlen($target)])];
        $index=new \ArrayObject(['v'=>'1','tag'=>$tag,'files'=>[new \ArrayObject(['index'=>'0','entries'=>[new \ArrayObject(['path'=>['Main.php'],'offsets'=>array_map(fn($i)=>(string)($i*96),range(0,7))])]])]]);
        $raw=Json::encode($index);$parsed=\AuthGo\PayloadWatermark::parse($raw,$files);$targets=['Main.php'=>$target];$targets['Main.php'][strlen($target)-1]='1';
        self::error('PAYLOAD_INVALID',function()use(&$targets,$parsed){\AuthGo\PayloadWatermark::apply($targets,$parsed,0,str_repeat("\0",32).str_repeat("\x19",32));});self::equal($targets['Main.php'][32],'0');$targets['Main.php'][strlen($target)-1]='0';
        \AuthGo\PayloadWatermark::apply($targets,$parsed,0,str_repeat("\0",32).str_repeat("\x19",32));self::equal(substr($targets['Main.php'],32,64),str_repeat('19',32));
        foreach([str_replace('"v":"1"','"v":2',$raw),str_replace('Main.php','../Main.php',$raw),str_replace('"96"','"95"',$raw),str_replace('"v":"1"','"v":"1","v":"1"',$raw)] as $bad)self::error('PAYLOAD_INVALID',fn()=>\AuthGo\PayloadWatermark::parse($bad,$files));
    }

    public static function run(): void
    {
        self::watermarkV2();
        self::$cases=0;
        self::case('cross-language vectors',self::vectors(...));
        self::case('v2 post-signature valid watermark tamper rejects signature without payload cache',self::watermarkSignatureTamperV2(...));
        self::case('NOT_ACTIVATED and restored cache',fn()=>self::fixture(function($f){self::error('SDK_NOT_ACTIVATED',fn()=>$f->client->unlockPayload($f->payload));self::equal(count($f->server->calls),0);$f->client->check(self::LICENSE);$restored=$f->server->client($f->dir);$calls=count($f->server->calls);self::error('SDK_NOT_ACTIVATED',fn()=>$restored->unlockPayload($f->payload));self::equal(count($f->server->calls),$calls);},false));
        self::case('authenticated unlock encrypted files only',fn()=>self::fixture(function($f){self::equal(count($f->caches()),1);$file=$f->caches()[0];$raw=file_get_contents($file);self::check(str_starts_with($raw,PayloadCache::PREFIX));self::check(!str_contains($raw,Client::b64($f->server->key)));self::check(!str_contains($file,self::LICENSE));self::check(!(glob($f->dir.'/*proof*')?:[]));self::error('SDK_CACHE_UNAVAILABLE',fn()=>$f->client->loadPayloadKey($f->payload,new Result($f->client,new \ArrayObject(),'','','offline')));}));
        self::case('offline ticket avoids repeated network timeout',fn()=>self::fixture(function($f){$f->server->floating=true;$f->prime();$f->server->now+=25;$f->server->mode='network';self::equal($f->client->check(self::LICENSE)->status,'grace');$calls=count($f->server->calls);self::equal($f->client->unlockPayload($f->payload),$f->server->key);self::equal(count($f->server->calls),$calls);$restored=$f->server->client($f->dir);self::equal($restored->check(self::LICENSE)->status,'grace');$calls=count($f->server->calls);self::equal($restored->unlockPayload($f->payload),$f->server->key);self::equal(count($f->server->calls),$calls);},false));
        self::case('tamper permissions symlink and size',fn()=>self::fixture(function($f){$file=$f->caches()[0];$raw=file_get_contents($file);file_put_contents($file,PayloadCache::PREFIX.Client::b64(str_repeat("\0",60)));self::error('SDK_CACHE_INVALID',fn()=>$f->client->loadPayloadKey($f->payload,$f->result));file_put_contents($file,$raw);chmod($file,0644);self::error('SDK_CACHE_UNAVAILABLE',fn()=>$f->client->loadPayloadKey($f->payload,$f->result));chmod($file,0600);file_put_contents($file,str_repeat('x',257));self::error('SDK_CACHE_UNAVAILABLE',fn()=>$f->client->loadPayloadKey($f->payload,$f->result));unlink($file);$target=$f->dir.'/target';file_put_contents($target,$raw);chmod($target,0600);symlink($target,$file);self::error('SDK_CACHE_UNAVAILABLE',fn()=>$f->client->loadPayloadKey($f->payload,$f->result));$f->client->savePayloadKey($f->payload,$f->result,$f->server->key.str_repeat("\x19",32));self::check(is_link($file));self::equal(file_get_contents($target),$raw);}));
        self::case('atomic replacement rejects inode substitution',fn()=>self::fixture(function($f){$file=$f->caches()[0];$raw=file_get_contents($file);clearstatcache(true,$file);$before=lstat($file);$handle=fopen($file,'rb');try{$temp=$f->dir.'/replacement';file_put_contents($temp,$raw);chmod($temp,0600);rename($temp,$file);self::error('SDK_CACHE_INVALID',fn()=>PayloadCache::verifyHandle($file,$handle,$before));}finally{fclose($handle);}self::equal($f->client->loadPayloadKey($f->payload,$f->result),$f->server->key.str_repeat("\x19",32));$f->client->savePayloadKey($f->payload,$f->result,'x');self::equal(file_get_contents($file),$raw);self::equal($f->client->unlockPayload($f->payload),$f->server->key);self::check(!(glob($f->dir.'/*.tmp')?:[]));}));
        self::case('unwritable storage best effort',fn()=>self::fixture(function($f){$path=$f->dir.'/not-directory';file_put_contents($path,'file');$client=$f->server->client($path);$client->check(self::LICENSE);self::equal($client->unlockPayload($f->payload),$f->server->key);},false));
        self::case('memory cache never persists keys',fn()=>self::fixture(function($f){$client=$f->server->client('');$result=$client->check(self::LICENSE);self::equal($client->unlockPayload($f->payload),$f->server->key);self::error('SDK_CACHE_UNAVAILABLE',fn()=>$client->loadPayloadKey($f->payload,$result));self::equal(count($f->caches()),0);},false));
        self::case('trial and zero grace clear old keys',fn()=>self::fixture(function($f){foreach(['trial','zero'] as $mode){$f->server->mode='';$f->client->verify();$f->client->unlockPayload($f->payload);self::equal(count($f->caches()),1);$f->server->mode=$mode;self::equal($f->client->unlockPayload($f->payload),$f->server->key);self::equal(count($f->caches()),0);}}));
        self::case('ordinary authorization and deactivate cleanup',fn()=>self::fixture(function($f){$f->server->trial=true;$f->client->verify();self::equal(count($f->caches()),0);$f->server->trial=false;$f->client->verify();$f->client->unlockPayload($f->payload);self::equal(count($f->caches()),1);$f->client->deactivate();self::equal(count($f->caches()),0);self::error('SDK_NOT_ACTIVATED',fn()=>$f->client->unlockPayload($f->payload));}));
        self::case('cache scope proof untouched and license binding',fn()=>self::fixture(function($f){$other=$f->server->client($f->dir,str_repeat('b',64));$other->check(self::LICENSE);$other->unlockPayload($f->payload);$proof=$f->dir.'/authgo-payload-proof-v1-untouched.cache';file_put_contents($proof,'untouched');$g=clone $f->result->data;$g['license_id']=43;self::error('SDK_CACHE_INVALID',fn()=>$f->client->loadPayloadKey($f->payload,self::result($f,$g)));$f->client->clearPayloadKeys();self::equal(count($f->caches()),1);self::equal(file_get_contents($proof),'untouched');}));
        self::case('cache expiry future issue and starts_at',fn()=>self::fixture(function($f){$g=clone $f->result->data;$g['grace_until']=self::iso($f->server->now);self::error('SDK_GRACE_EXPIRED',fn()=>$f->client->loadPayloadKey($f->payload,self::result($f,$g)));$g['issued_at']=self::iso($f->server->now+301);$g['grace_until']=self::iso($f->server->now+500);self::error('SDK_GRACE_EXPIRED',fn()=>$f->client->loadPayloadKey($f->payload,self::result($f,$g)));$g['issued_at']=self::iso($f->server->now);$g['starts_at']=self::iso($f->server->now+1);self::error('LICENSE_NOT_STARTED',fn()=>$f->client->loadPayloadKey($f->payload,self::result($f,$g)));}));
        self::case('grace exact expiry license expiry and rollback',fn()=>self::fixture(function($f){$initial=$f->server->now;$f->server->now+=120;self::error('SDK_GRACE_EXPIRED',fn()=>$f->client->loadPayloadKey($f->payload,$f->result));$f->client->clearPayloadKeys();$f->client->savePayloadKey($f->payload,$f->result,$f->server->key.str_repeat("\x19",32));self::equal(count($f->caches()),0);$f->server->now=$initial-301;self::error('SDK_CLOCK_ROLLBACK',fn()=>$f->client->unlockPayload($f->payload));$f->server->now=$initial;$g=clone $f->result->data;$g['expires_at']=self::iso($initial);self::error('LICENSE_EXPIRED',fn()=>$f->client->loadPayloadKey($f->payload,self::result($f,$g)));}));
        self::case('authenticated refusals clear unlock verify heartbeat',fn()=>self::fixture(function($f){foreach(['LICENSE_REVOKED','VERSION_DISABLED','MAINTENANCE_EXPIRED','UNKNOWN_NEW_REFUSAL'] as $code)foreach([0,1,2] as $op){$f->server->code='';$f->prime();$f->server->code=$code;self::error($code,function()use($f,$op){match($op){0=>$f->client->unlockPayload($f->payload),1=>$f->client->verify(),2=>$f->client->heartbeat()};});self::equal(count($f->caches()),0);self::error('SDK_NOT_ACTIVATED',fn()=>$f->client->unlockPayload($f->payload));}},false));
        self::case('instance replacement preserves proof clears keys',fn()=>self::fixture(function($f){$before=clone self::property($f->client,'state');$f->server->code='INSTANCE_REPLACED';self::error('INSTANCE_REPLACED',fn()=>$f->client->unlockPayload($f->payload));self::equal(count($f->caches()),0);self::error('SDK_NOT_ACTIVATED',fn()=>$f->client->unlockPayload($f->payload));self::error('INSTANCE_REPLACED',fn()=>$f->client->verify());$after=self::property($f->client,'state');self::equal($before['ticket'],$after['ticket']);self::equal($before['seed'],$after['seed']);self::check(!($after['refused']??false));}));
        self::case('PAYLOAD_INVALID and channel failures preserve keys',fn()=>self::fixture(function($f){$file=$f->caches()[0];$raw=file_get_contents($file);foreach(['network','status','html','signature','nonce',''] as $mode){$f->server->mode=$mode;$f->server->code=$mode===''?'PAYLOAD_INVALID':'';self::equal($f->client->unlockPayload($f->payload),$f->server->key);self::equal(file_get_contents($file),$raw);}$f->client->clearPayloadKeys();self::error('PAYLOAD_INVALID',fn()=>$f->client->unlockPayload($f->payload));self::check(in_array('PAYLOAD_INVALID',Client::TEMPORARY,true));}));
        self::case('wrap schema recovers null and invalid strings do not',fn()=>self::fixture(function($f){foreach([17,true,new \ArrayObject(),[]] as $value){$f->server->changes=['e'=>$value];self::equal($f->client->unlockPayload($f->payload),$f->server->key);}$f->server->changes=[];$f->server->mode='missing-wrap';self::equal($f->client->unlockPayload($f->payload),$f->server->key);$f->server->mode='';foreach([null,'bad','='] as $value){$f->server->changes=['e'=>$value];self::error('SDK_RESPONSE_INVALID',fn()=>$f->client->unlockPayload($f->payload));}}));
        self::case('fresh malformed grant or unwrap never uses cache',fn()=>self::fixture(function($f){$file=$f->caches()[0];$raw=file_get_contents($file);foreach(['challenge','license','seed','issued','wrap'] as $mode){$f->server->mode=$mode;self::error($mode==='issued'?'SDK_RESPONSE_TIMESTAMP_INVALID':'SDK_RESPONSE_INVALID',fn()=>$f->client->unlockPayload($f->payload));self::equal(file_get_contents($file),$raw);}$f->server->mode='';$f->server->grantChanges=['is_trial'=>'true'];self::error('SDK_RESPONSE_INVALID',fn()=>$f->client->unlockPayload($f->payload));$f->server->grantChanges=[];$f->server->changes=['ticket'=>'bad'];self::error('SDK_RESPONSE_SIGNATURE_INVALID',fn()=>$f->client->unlockPayload($f->payload));}));
        self::case('copy rename into another instance rejected',fn()=>self::fixture(function($f){$other=$f->server->client($f->dir,str_repeat('c',64));$r=$other->check(self::LICENSE);$cache=self::property($other,'payloadCache');[$file]=$cache->material($f->payload,$r->data,$f->server->now);copy($f->caches()[0],$file);chmod($file,0600);self::error('SDK_CACHE_INVALID',fn()=>$other->loadPayloadKey($f->payload,$r));}));
        self::case('strict schema aliases duplicates and config binding',fn()=>self::fixture(function($f){$original=$f->payload->toObject();foreach($original as $key=>$value){$wrong=clone $original;unset($wrong[$key]);self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}foreach(['null','[]','{}','{"v":2,"v":2}','{"v":null,"v":2}',str_repeat('{',66000)] as $raw)self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload($raw));foreach(['v'=>true,'key_id'=>"bad.key",'version'=>'1.2.3-01','built_at'=>'2026-02-30T00:00:00Z','app_key'=>str_repeat('a',257),'manifest'=>'__==','App_Key'=>'wrong','config'=>'authgo2.bad'] as $key=>$value){$wrong=clone $original;$wrong[$key]=$value;self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}$config=Json::parse(Client::decode(substr($f->payload->config,8)));$config['app_secret']='changed';$changed=clone $original;$changed['config']='authgo2.'.Client::b64(Json::encode($config));self::check(Payload::parsePayload(Json::encode($changed))->payloadBinding()!==$f->payload->payloadBinding());$f->prime();$config['app_key']='other-app';$changed['app_key']='other-app';$changed['config']='authgo2.'.Client::b64(Json::encode($config));$wrongApp=Payload::parsePayload(Json::encode($changed));$calls=count($f->server->calls);self::error('PAYLOAD_INVALID',fn()=>$f->client->unlockPayload($wrongApp));self::equal(count($f->server->calls),$calls);},false));
        self::case('JSON boundary UTC and precise 64-bit integers',fn()=>self::fixture(function($f){$raw=Json::encode($f->payload->toObject());self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload('{"v":null,'.substr($raw,1)));Payload::parsePayload($raw.str_repeat(' ',65536-strlen($raw)));self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload($raw.str_repeat(' ',65537-strlen($raw))));foreach(['2.0','2e0','"2"'] as $token)self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(str_replace('"v":2','"v":'.$token,$raw)));$manifest=Json::parse(Client::decode($f->payload->manifest));$file=$manifest['files'][0];foreach(['0',-1,new JsonNumber('4611686018427387904')] as $size){$file['size']=$size;$wrong=$f->payload->toObject();$wrong['manifest']=Client::b64(Json::encode($manifest));self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}$file['size']=new JsonNumber('4611686018427387903');$good=$f->payload->toObject();$good['manifest']=Client::b64(Json::encode($manifest));Payload::parsePayload(Json::encode($good));foreach(['python_version','main_class','architecture'] as $field){$m=Json::parse(Json::encode($manifest));$m['files'][0][$field]=null;$wrong=$f->payload->toObject();$wrong['manifest']=Client::b64(Json::encode($m));self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}foreach(['2026-02-29T00:00:00Z','2026-11-07T24:00:00Z','2026-11-07T00:60:00Z','2026-11-07T00:00:60Z','2026-11-07T00:00:00+00:00'] as $date){$wrong=$f->payload->toObject();$wrong['built_at']=$date;self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}$leap=$f->payload->toObject();$leap['built_at']='0000-02-29T00:00:00Z';Payload::parsePayload(Json::encode($leap));$f->server->id=new JsonNumber('9007199254740993');$f->prime();self::equal($f->client->loadPayloadKey($f->payload,$f->result),$f->server->key.str_repeat("\x19",32));$cache=self::property($f->client,'payloadCache');[,,$aad]=$cache->material($f->payload,$f->result->data,$f->server->now);self::equal(bin2hex(substr($aad,-8)),'0020000000000001');$g=clone $f->result->data;$g['license_id']=new JsonNumber('18446744073709551615');[,,$aad]=$cache->material($f->payload,$g,$f->server->now);self::equal(bin2hex(substr($aad,-8)),'ffffffffffffffff');},false));
        self::case('Go HTTPS predicate not parse_url normalization',fn()=>self::fixture(function($f){$config=Json::parse(Client::decode(substr($f->payload->config,8)));foreach(['http://host','https:host','https:///host',"https://host\n",' https://host','https://user@host','https://host?x=1','https://host#x','https://host:abc','https://ho%41st','https://ho{st','https://ho|st','https://ho}st','https://host/path%zz'] as $url)foreach(['url'] as $field){$c=clone $config;$c[$field]=$field==='url'?$url:[$url];$wrong=$f->payload->toObject();$wrong['config']='authgo2.'.Client::b64(Json::encode($c));self::error('PAYLOAD_INVALID',fn()=>Payload::parsePayload(Json::encode($wrong)));}foreach(['HTTPS://host','https://ho]st','https://[syntactic-host]','https://host:65536','https://host:','https://host/path space','https://host/path?','https://host#'] as $url){$c=clone $config;$c['url']=$url;$good=$f->payload->toObject();$good['config']='authgo2.'.Client::b64(Json::encode($c));Payload::parsePayload(Json::encode($good));}},false));
        self::case('unwrap rejects changed binding low-order and challenge',function(){$v=self::vector('payload-unlock-v2.json');$p=Payload::parsePayload(Json::encode($v['payload']));$raw=$p->toObject();$raw['version']='2.0.0';$other=Payload::parsePayload(Json::encode($raw));$wrap=$v['response']->getArrayCopy();$private=hex2bin($v['client_private_hex']);$challenge=hex2bin($v['challenge_hex']);self::error('SDK_RESPONSE_INVALID',fn()=>$other->unwrap($wrap,$private,$challenge));$bad=$wrap;$bad['e']=Client::b64(str_repeat("\0",32));self::error('SDK_RESPONSE_INVALID',fn()=>$p->unwrap($bad,$private,$challenge));self::error('SDK_RESPONSE_INVALID',fn()=>$p->unwrap($wrap,$private,str_repeat("\0",32)));});
        self::case('worker serialization and nested guard lock',self::serial(...));
        self::case('release-seat refusal cleanup',fn()=>self::fixture(function($f){$f->server->floating=true;$f->prime();$f->server->code='LICENSE_REVOKED';self::error('LICENSE_REVOKED',fn()=>$f->client->releaseSeat());self::equal(count($f->caches()),0);self::error('SDK_NOT_ACTIVATED',fn()=>$f->client->unlockPayload($f->payload));},false));
        echo '{"language":"php","payload_tests":"PASS","tests":'.self::$cases.'}'.PHP_EOL;
    }
    private static function serial(): void
    {
        self::fixture(function($f){
            // The same lock and nested calls used by FPM/Apache, exercised across real PHP processes.
            $first=null;$second=null;$pipes1=[];$pipes2=[];
            try {
                $first=proc_open([PHP_BINARY,__FILE__,'lock-worker',$f->dir],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes1);self::check(is_resource($first));
                stream_set_timeout($pipes1[1],5);self::equal(trim((string)fgets($pipes1[1])),'READY');self::equal(trim((string)fgets($pipes1[1])),'ENTER');
                $second=proc_open([PHP_BINARY,__FILE__,'lock-worker',$f->dir],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes2);self::check(is_resource($second));
                stream_set_timeout($pipes2[1],5);self::equal(trim((string)fgets($pipes2[1])),'READY');
                $read=[$pipes2[1]];$write=null;$except=null;
                self::equal(stream_select($read,$write,$except,0,200000),0); // Second process cannot enter while the first owns the SDK lock.
                fwrite($pipes1[0],"GO\n");fflush($pipes1[0]);self::equal(trim((string)fgets($pipes1[1])),'DONE');
                stream_set_timeout($pipes2[1],5);self::equal(trim((string)fgets($pipes2[1])),'ENTER');fwrite($pipes2[0],"GO\n");fflush($pipes2[0]);self::equal(trim((string)fgets($pipes2[1])),'DONE');
                foreach([$pipes1,$pipes2] as $pipes){fclose($pipes[0]);self::equal(stream_get_contents($pipes[2]),'');fclose($pipes[1]);fclose($pipes[2]);}
                self::equal(proc_close($first),0);$first=null;self::equal(proc_close($second),0);$second=null;
                self::equal(count($f->caches()),1);
                self::requests($f);
            }finally{foreach([$first,$second] as $p)if(is_resource($p)){proc_terminate($p);proc_close($p);}}
        },false);
    }
    private static function requests(PayloadTestFixture $fixture): void
    {
        $socket=stream_socket_server('tcp://127.0.0.1:0',$errno,$error);self::check(is_resource($socket));
        $address=stream_socket_get_name($socket,false);fclose($socket);$log=$fixture->dir.'/http.log';$pipes=[];$process=null;
        try {
            $process=proc_open([PHP_BINARY,'-S',$address,__FILE__],[0=>['pipe','r'],1=>['file',$log,'a'],2=>['file',$log,'a']],$pipes);self::check(is_resource($process));
            $end=microtime(true)+5;
            while(!str_contains((string)@file_get_contents($log),'Development Server')){self::check(microtime(true)<$end&&proc_get_status($process)['running']);usleep(10000);clearstatcache(true,$log);}
            $url='http://'.$address.'/?payload_fixture='.rawurlencode($fixture->dir);
            $context=stream_context_create(['http'=>['timeout'=>5]]);
            $first=json_decode(file_get_contents($url,false,$context),true,512,JSON_THROW_ON_ERROR);
            $second=json_decode(file_get_contents($url,false,$context),true,512,JSON_THROW_ON_ERROR);
            self::check($first['request_style']&&$second['request_style']&&$first['key_ok']&&$second['key_ok']);
            self::equal($first['cached'],false);self::equal($second['cached'],true);self::equal($second['ops'],['payload.unlock']);
        }finally{if(isset($pipes[0])&&is_resource($pipes[0]))fclose($pipes[0]);if(is_resource($process)){proc_terminate($process);proc_close($process);}}
    }
    public static function requestWorker(string $directory): void
    {
        if(dirname($directory)!==sys_get_temp_dir()||!preg_match('/\Aauthgo-payload-[a-f0-9]{24}\z/D',basename($directory))||!is_dir($directory))throw new \RuntimeException('test fixture');
        $f=new PayloadTestFixture($directory);$cached=false;
        $key=$f->client->guardLocked(function()use($f,&$cached): string {
            $restored=$f->client->guardCached(self::LICENSE);$cached=$restored!==null;
            if($restored){$f->result=$restored[0];}
            else{$f->result=$f->client->check(self::LICENSE);$f->client->guardPersist($f->result,$f->server->now+10,$f->server->now+5);}
            return $f->client->unlockPayload($f->payload);
        });
        header('Content-Type: application/json');echo json_encode(['request_style'=>!\AuthGo\isPersistentRuntime(),'cached'=>$cached,'key_ok'=>$key===$f->server->key,'ops'=>$f->server->calls],JSON_THROW_ON_ERROR);
        sodium_memzero($key);
    }
    public static function worker(string $directory): void
    {
        $f=new PayloadTestFixture($directory);echo "READY\n";flush();
        $f->client->guardLocked(function()use($f){
            $critical=$f->dir.'/critical';$marker=@fopen($critical,'x');self::check(is_resource($marker));
            try {
                echo "ENTER\n";flush();if(trim((string)fgets(STDIN))!=='GO')throw new \RuntimeException('worker command');
                // Reentry must keep the outer lock and avoid reloading partial in-memory state.
                $f->client->guardLocked(function()use($f){$f->prime();self::equal($f->client->loadPayloadKey($f->payload,$f->result),$f->server->key.str_repeat("\x19",32));});
                echo "DONE\n";flush();
            }finally{fclose($marker);@unlink($critical);}
        });
    }
}
if(!\AuthGo\isPersistentRuntime()&&isset($_GET['payload_fixture'])){PayloadTests::requestWorker($_GET['payload_fixture']);return;}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){if(($argv[1]??'')==='lock-worker')PayloadTests::worker($argv[2]);else PayloadTests::run();}
