<?php
declare(strict_types=1);
require_once __DIR__.'/payload.php';
use AuthGo\{Client,Guard,Payload,Json,SealedArchive,Error};

final class SealedTests
{
    private static int $passed=0;
    public static function check(bool $ok): void {if(!$ok)throw new \RuntimeException('sealed assertion');}
    private static function fails(callable $fn,?string $code=null): void
    {
        try{$fn();}catch(Error $e){self::check($code===null||$e->errorCode===$code);return;}
        throw new \RuntimeException('sealed expected rejection');
    }
    public static function tar(array $files): string
    {
        $out='';foreach($files as [$name,$bytes,$type]) {
            $prefix='';if(strlen($name)>100){$split=strrpos($name,'/');if($split===false)throw new RuntimeException('test tar path');$prefix=substr($name,0,$split);$name=substr($name,$split+1);}
            $h=str_repeat("\0",512);
            foreach([[0,100,$name],[100,8,"0000600\0"],[108,8,"0000000\0"],[116,8,"0000000\0"],[124,12,sprintf('%011o',strlen($bytes))."\0"],[136,12,"00000000000\0"],[148,8,str_repeat(' ',8)],[156,1,$type],[257,8,"ustar\00000"],[345,155,$prefix]] as [$at,$n,$v])$h=substr_replace($h,str_pad($v,$n,"\0"),$at,$n);
            $h=substr_replace($h,sprintf('%06o',array_sum(unpack('C*',$h)))."\0 ",148,8);
            $out.=$h.$bytes.str_repeat("\0",(512-strlen($bytes)%512)%512);
        }
        return $out.str_repeat("\0",1024);
    }
    public static function files(): array
    {
        return [['bootstrap.php', '<?php require __DIR__."/lib/value.php"; return include "lib/relative.php";', '0'],
            ['lib/value.php','<?php $GLOBALS["sealed_value"]="AUTHGO_PHP_SEALED_PLAINTEXT_MARKER";','0'],
            ['lib/relative.php','<?php return include __DIR__."/../answer.php";','0'],
            ['answer.php','<?php return 42;','0'],['later.php','<?php return 99;','0'],
            ['Auto/Thing.php','<?php namespace SealedQA; final class Thing {public static function value(){return 73;}}','0']];
    }
    public static function fixture(?string $tar=null,array $names=['core']): array
    {
        $f=new PayloadTestFixture();$tar??=self::tar(self::files());$entries=[];
        $tag='0123456789abcdef0123456789abcdef';$slot=$tag.str_repeat('0',64);$carrier='<?php /*'.str_repeat($slot,8).'*/';
        $offsets=[];for($i=0;$i<8;$i++)$offsets[]=(string)(8+$i*96);
        $addition=self::tar([['__authgo_carrier.php',$carrier,'0']]);
        $tar=($tar===str_repeat("\0",1024)?"":substr($addition,0,-1024)).$tar;
        foreach($names as $i=>$name)$entries[]=['name'=>$name,'kind'=>'php','path'=>sprintf('%08d.agc',$i),'size'=>strlen($tar),'chunk_size'=>1048576,'encoding'=>'tar'];
        $privateFiles=[];foreach($entries as $i=>$_)$privateFiles[]=['index'=>(string)$i,'entries'=>[['path'=>['__authgo_carrier.php'],'offsets'=>$offsets]]];
        $private=Json::encode(['v'=>'1','tag'=>$tag,'files'=>$privateFiles]);$meta=count($entries);
        $entries[]=['name'=>'__authgo_watermark','kind'=>'watermark','path'=>sprintf('%08d.agc',$meta),'size'=>strlen($private),'chunk_size'=>1048576,'encoding'=>'raw'];
        $manifest=Client::b64(Json::encode(['files'=>$entries]));
        $p=$f->payload;$p=new Payload(2,$p->appKey,$p->version,$p->builtAt,$p->keyId,$p->config,$manifest,$p->e,$p->n,$p->c);
        $f->payload=$f->server->payload=$p;file_put_contents($f->dir.'/payload.json',Json::encode($p->toObject()));
        foreach($names as $i=>$_)self::encrypt($f,$tar,$i);self::encrypt($f,$private,$meta);putenv('AUTHGO_PAYLOAD_DIR='.$f->dir);
        $guard=Guard::start(['config'=>'authgo2.'.Client::b64(Json::encode($f->server->config)),'license'=>PayloadTests::LICENSE,'version'=>$p->version,
            'sdk_options'=>['cache_dir'=>$f->dir,'fingerprint'=>PayloadTests::FP,'clock'=>fn()=>$f->server->now,'transport'=>$f->server->transport(...)]]);
        return [$f,$guard];
    }
    public static function encrypt(PayloadTestFixture $f,string $tar,int $index=0): void
    {
        $out='';$count=max(1,(int)ceil(strlen($tar)/1048576));
        for($j=0;$j<$count;$j++){$nonce=pack('N3',$index,0,$j);$aad="authgo-payload-chunk-v1\0".$f->payload->payloadBinding().$nonce.chr((int)($j===$count-1));$out.=Client::seal($f->server->key,$nonce,substr($tar,$j*1048576,1048576),$aad);}
        file_put_contents($f->dir.'/'.sprintf('%08d.agc',$index),$out);
    }
    private static function test(string $name,callable $fn,?string $tar=null): void
    {
        [$f,$g]=self::fixture($tar);
        try{$fn($f,$g);self::$passed++;echo 'sealed '.$name." PASS\n";}
        finally{try{$g->close();}catch(Error){}$f->clean();putenv('AUTHGO_PAYLOAD_DIR');unset($GLOBALS['sealed_value']);}
    }
    private static function watermarkLoaderV2(): void
    {
        $f=new PayloadTestFixture();$tag=str_repeat('a',32);$slot=$tag.str_repeat('0',64);
        $source='<?php return [';for($i=0;$i<8;$i++)$source.=($i?',':'')."'".$i.$slot."'";$source.='];';
        $offsets=[];$at=0;while(($at=strpos($source,$slot,$at))!==false){$offsets[]=(string)$at;$at+=96;}self::check(count($offsets)===8);
        $tar=self::tar([['entry.php',$source,'0']]);
        $index=Json::encode(new \ArrayObject(['v'=>'1','tag'=>$tag,'files'=>[new \ArrayObject(['index'=>'0','entries'=>[new \ArrayObject(['path'=>['entry.php'],'offsets'=>$offsets])]])]]));
        $public=[['name'=>'core','kind'=>'php','path'=>'00000000.agc','size'=>strlen($tar),'chunk_size'=>1048576,'encoding'=>'tar'],['name'=>'__authgo_watermark','kind'=>'watermark','path'=>'00000001.agc','size'=>strlen($index),'chunk_size'=>1048576,'encoding'=>'raw']];
        $p=$f->payload;$p=new Payload(2,$p->appKey,$p->version,$p->builtAt,$p->keyId,$p->config,Client::b64(Json::encode(['files'=>$public])),$p->e,$p->n,$p->c);
        $f->payload=$f->server->payload=$p;file_put_contents($f->dir.'/payload.json',Json::encode($p->toObject()));self::encrypt($f,$tar,0);self::encrypt($f,$index,1);putenv('AUTHGO_PAYLOAD_DIR='.$f->dir);$g=null;
        try {
            $g=Guard::start(['config'=>'authgo2.'.Client::b64(Json::encode($f->server->config)),'license'=>PayloadTests::LICENSE,'sdk_options'=>['cache_dir'=>$f->dir,'fingerprint'=>PayloadTests::FP,'clock'=>fn()=>$f->server->now,'transport'=>$f->server->transport(...)]]);
            $g->installSealed('core');$values=require 'authgo-sealed://core/entry.php';foreach($values as $v)self::check(substr($v,33)===str_repeat('19',32));
            self::check(file_get_contents($f->dir.'/00000000.agc')!==$tar);
        }finally{if($g!==null)$g->close();$f->clean();putenv('AUTHGO_PAYLOAD_DIR');}
    }

    public static function run(): void
    {
        self::watermarkLoaderV2();
        self::test('Go-chunk-vectors-empty-multifile-multichunk',function($f,$g){
            $v=PayloadTests::vector('payload-envelope.json');$p=Payload::parsePayload(Json::encode($v['payload']));$key=hex2bin($v['content_key_hex']);$cipher=[];$plain=[];
            foreach($v['chunks'] as $chunk){
                $i=(int)$chunk['file']->raw;$bytes=isset($chunk['plain_repeat_count'])?str_repeat(hex2bin($chunk['plain_repeat_hex']),(int)$chunk['plain_repeat_count']->raw):hex2bin($chunk['plain_hex']);
                $block=Client::seal($key,hex2bin($chunk['nonce_hex']),$bytes,hex2bin($chunk['aad_hex']));
                if(isset($chunk['cipher_hex']))self::check(bin2hex($block)===$chunk['cipher_hex']);
                else self::check(hash('sha256',$block)===$chunk['cipher_sha256_hex']);
                $cipher[$i]=($cipher[$i]??'').$block;$plain[$i]=($plain[$i]??'').$bytes;
            }
            foreach($cipher as $i=>$bytes){
                $path=$f->dir.'/vector.agc';file_put_contents($path,$bytes);$h=fopen($path,'rb');
                try{self::check(SealedArchive::decrypt($h,$p,$key,$i,strlen($plain[$i]))===$plain[$i]);}finally{fclose($h);}
            }
            $path=$f->dir.'/vector.agc';file_put_contents($path,$cipher[1]);$h=fopen($path,'rb');
            try{self::fails(fn()=>SealedArchive::decrypt($h,$p,$key,0,strlen($plain[1])),'PAYLOAD_INVALID');}finally{fclose($h);sodium_memzero($key);}
        });
        self::test('relative/include/require/canonical-once/autoload',function($f,$g){
            $g->installSealed('core');self::check((require 'authgo-sealed://core/bootstrap.php')===42);
            self::check($GLOBALS['sealed_value']==='AUTHGO_PHP_SEALED_PLAINTEXT_MARKER');
            $load=static function($name){if($name==='SealedQA\\Thing')require 'authgo-sealed://core/Auto/Thing.php';};
            spl_autoload_register($load);try{self::check(SealedQA\Thing::value()===73);}finally{spl_autoload_unregister($load);}
            require_once 'authgo-sealed://core/./Auto/Thing.php';
            self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');
            foreach(new RecursiveIteratorIterator(new RecursiveDirectoryIterator($f->dir,FilesystemIterator::SKIP_DOTS)) as $file)self::check(!str_contains(file_get_contents($file->getPathname()),'AUTHGO_PHP_SEALED_PLAINTEXT_MARKER'));
            self::check(count($f->caches())===1);
        });
        self::test('read/seek/stat/readonly/strict-url',function($f,$g){
            $g->installSealed('core');$h=fopen('authgo-sealed://core/answer.php','rb');self::check(fstat($h)['size']===16);self::check(fread($h,5)==='<?php');self::check(fseek($h,-3,SEEK_END)===0);self::check(fread($h,3)==='42;');self::check(fseek($h,100)===-1);fclose($h);
            self::check(@fopen('authgo-sealed://core/answer.php','wb')===false);
            foreach(['../answer.php','%61nswer.php','answer.php?x','answer.php#x','a//b.php','a\\b.php','/answer.php','missing.php'] as $bad)self::fails(fn()=>fopen('authgo-sealed://core/'.$bad,'rb'));
        });
        self::test('authenticated-refusal-purges-open-handles',function($f,$g){
            $g->installSealed('core');$h=fopen('authgo-sealed://core/later.php','rb');self::check(fread($h,1)==='<');$f->server->code='LICENSE_REVOKED';$f->server->now+=11;
            self::fails(fn()=>$g->tick(),'LICENSE_REVOKED');self::check($g->done()&&count($f->caches())===0);
            self::fails(fn()=>require 'authgo-sealed://core/later.php');self::check(!is_resource($h));
        });
        self::test('active-stream-refusal-safe-unwind',function($f,$g){
            $g->installSealed('core');$h=fopen('authgo-sealed://core/later.php','rb');
            self::check(fread($h,8192)==='<?php return 99;');$f->server->code='LICENSE_REVOKED';$f->server->now+=11;
            self::fails(fn()=>fread($h,8192),'LICENSE_REVOKED');
            if(is_resource($h))fclose($h);
            self::fails(fn()=>require 'authgo-sealed://core/later.php');
        });
        self::test('close-clears-without-deleting-valid-key',function($f,$g){$g->installSealed('core');$g->close();self::fails(fn()=>require 'authgo-sealed://core/later.php');self::check(count($f->caches())===1);});
        self::test('tick-on-load-no-background-loop',function($f,$g){$g->installSealed('core');$f->server->code='LICENSE_REVOKED';$f->server->now+=11;self::fails(fn()=>require 'authgo-sealed://core/later.php','LICENSE_REVOKED');});
        self::test('offline-key-valid-until-original-grace',function($f,$g){$g->installSealed('core');$f->server->mode='network';$f->server->now+=11;self::check((require 'authgo-sealed://core/later.php')===99);$f->server->now+=121;self::fails(fn()=>require 'authgo-sealed://core/answer.php');});
        self::test('trial-no-key-on-disk',function($f,$g){$f->server->trial=true;$g->installSealed('core');self::check(count($f->caches())===0);self::check((require 'authgo-sealed://core/later.php')===99);});
        self::test('unlock-refusal-latches-guard',function($f,$g){$f->server->code='VERSION_DISABLED';self::fails(fn()=>$g->installSealed('core'),'VERSION_DISABLED');self::check($g->done());self::fails(fn()=>require 'authgo-sealed://core/later.php');});
        self::test('ciphertext-tamper-not-published',function($f,$g){$path=$f->dir.'/00000000.agc';$b=file_get_contents($path);$b[-1]=chr(ord($b[-1])^1);file_put_contents($path,$b);self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');self::fails(fn()=>require 'authgo-sealed://core/answer.php');});
        self::test('ciphertext-size-and-symlink',function($f,$g){$path=$f->dir.'/00000000.agc';$b=file_get_contents($path);file_put_contents($path,$b.'x');self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');unlink($path);file_put_contents($f->dir.'/other',$b);symlink('other',$path);self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');});
        self::test('manifest-symlink',function($f,$g){rename($f->dir.'/payload.json',$f->dir.'/other');symlink('other',$f->dir.'/payload.json');self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');});
        self::test('utf8-path',function($f,$g){$g->installSealed('core');self::check((require 'authgo-sealed://core/包/类.php')===42);},self::tar([['包/类.php','<?php return 42;','0']]));
        self::test('ustar-prefix',function($f,$g){$g->installSealed('core');self::check((require 'authgo-sealed://core/'.str_repeat('a',120).'/x.php')===42);},self::tar([[str_repeat('a',120).'/x.php','<?php return 42;','0']]));
        self::test('empty-file',function($f,$g){$g->installSealed('core');self::check((require 'authgo-sealed://core/empty.php')===1);},self::tar([['empty.php','','0']]));
        self::test('invalid-name-and-unowned-namespace',function($f,$g){
            foreach(['','../core','Core','core/child',str_repeat('a',129)] as $name)self::fails(fn()=>$g->installSealed($name),'PAYLOAD_INVALID');
            $g->installSealed('core');self::fails(fn()=>require 'authgo-sealed://other/answer.php');
        });
        self::test('size-bomb-rejected-before-unlock',function($f,$g){
            $p=$f->payload;$m=Json::parse(Client::decode($p->manifest));$m['files'][0]['size']=SealedArchive::LIMIT+1;
            $p=new Payload(2,$p->appKey,$p->version,$p->builtAt,$p->keyId,$p->config,Client::b64(Json::encode($m)),$p->e,$p->n,$p->c);
            file_put_contents($f->dir.'/payload.json',Json::encode($p->toObject()));$calls=count($f->server->calls);
            self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');self::check(count($f->server->calls)===$calls);
        });
        self::test('temporary-unlock-error-retains-cache',function($f,$g){
            PayloadTests::equal($f->client->check(PayloadTests::LICENSE)->status,'online');
            $key=$f->client->unlockPayload($f->payload);sodium_memzero($key);$f->server->code='PAYLOAD_INVALID';
            $g->installSealed('core');self::check(count($f->caches())===1);self::check((require 'authgo-sealed://core/later.php')===99);
        });
        self::test('multi-chunk-final-tag',function($f,$g){$g->installSealed('core');self::check((require 'authgo-sealed://core/later.php')===99);},self::tar([['large.php','<?php /*'.str_repeat('x',1048576).'*/','0'],['later.php','<?php return 99;','0']]));
        self::test('late-tag-failure-no-partial-publication',function($f,$g){$p=$f->dir.'/00000000.agc';$b=file_get_contents($p);$b[-1]=chr(ord($b[-1])^1);file_put_contents($p,$b);self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID');self::fails(fn()=>require 'authgo-sealed://core/answer.php');},self::tar([['answer.php','<?php return 42;','0'],['big.php',str_repeat('x',1048576),'0']]));
        foreach(['../x.php','/x.php','a/./x.php','a//x.php','a/../x.php','a\\x.php','x%2ephp','x:php','x.php?y','x.php#y',"x\n.php",'data.txt'] as $path)
            self::test('tar-path-'.bin2hex($path),fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),self::tar([[$path,'<?php','0']]));
        foreach(['1','2','5','x','g','L','S'] as $kind)self::test('tar-type-'.$kind,fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),self::tar([['x.php','<?php',$kind]]));
        self::test('duplicate',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),self::tar([['x.php','a','0'],['x.php','b','0']]));
        self::test('file-directory-conflict',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),self::tar([['x.php','a','0'],['x.php/y.php','b','0']]));
        $tar=self::tar(self::files());$tar[0]='z';self::test('checksum',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),$tar);
        self::test('truncated-tar',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),substr(self::tar(self::files()),0,-1024));
        self::test('trailing-data',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),self::tar(self::files()).str_repeat('x',512));
        foreach([[124,12,"\x80".str_repeat("\0",11)],[124,12,"77777777777\0"],[100,8,"0000899\0"],[329,8,"0000001\0"],[257,8,"ustar  \0"],[0,100,"a.php\0hidden.php"]] as $case=>$mutation) {
            [$at,$len,$value]=$mutation;$tar=self::tar(self::files());$tar=substr_replace($tar,str_pad($value,$len,"\0"),$at,$len);
            $tar=substr_replace($tar,str_repeat(' ',8),148,8);$sum=array_sum(unpack('C*',substr($tar,0,512)));
            $tar=substr_replace($tar,sprintf('%06o',$sum)."\0 ",148,8);
            self::test('strict-header-'.$case,fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),$tar);
        }
        $tar=self::tar([['x.php','x','0']]);$tar[513]='x';self::test('nonzero-file-padding',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),$tar);
        self::test('empty-archive',fn($f,$g)=>self::fails(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'),str_repeat("\0",1024));
        echo 'PHP sealed tests: '.self::$passed." PASS\n";
    }
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__)SealedTests::run();
