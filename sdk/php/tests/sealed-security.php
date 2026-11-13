<?php
declare(strict_types=1);
require_once __DIR__.'/sealed.php';
use AuthGo\{Error,SealedStream,Guard,Client,Json};

/** Deliberately registered by tests only; never supplies protected source. */
final class ForeignSealedReviewStream
{
    public mixed $context;
    public function stream_open(string $path,string $mode,int $options,?string &$opened_path): bool {$opened_path=$path;return true;}
    public function stream_read(int $count): string {return '';}
    public function stream_eof(): bool {return true;}
    public function stream_close(): void {}
    public function stream_stat(): array {return ['size'=>0,'mode'=>0100400];}
}
final class SealedReviewTests
{
    private static int $passed=0;
    private static function check(bool $ok): void {if(!$ok)throw new RuntimeException('sealed review assertion');}
    private static function denies(callable $fn,?string $code=null): void
    {
        try{$fn();}catch(Error $e){self::check($code===null||$e->errorCode===$code);return;}
        throw new RuntimeException('sealed review expected denial');
    }
    private static function noBytes(mixed $handle): void
    {
        // Closing a buffered resource is sufficient. If the callback was active,
        // it may stay allocated but must never yield its native prefetch buffer.
        if(!is_resource($handle))return;
        self::denies(fn()=>fread($handle,8192));
    }
    private static function clean($f,$g): void {try{$g->close();}catch(Error){}$f->clean();}
    private static function foreign(callable $fn): void
    {
        $restore=in_array('authgo-sealed',stream_get_wrappers(),true);
        if($restore)self::check(stream_wrapper_unregister('authgo-sealed'));
        self::check(stream_wrapper_register('authgo-sealed',ForeignSealedReviewStream::class));
        try{$fn();}
        finally{stream_wrapper_unregister('authgo-sealed');if($restore)stream_wrapper_register('authgo-sealed',SealedStream::class);}
    }
    public static function reinstall(): void
    {
        [$f,$ga]=SealedTests::fixture();$gb=null;
        try {
            $ga->installSealed('core');self::check((require 'authgo-sealed://core/answer.php')===42);
            $handle=fopen('authgo-sealed://core/later.php','rb');self::check(fread($handle,1)==='<');
            $ga->close();self::noBytes($handle);self::denies(fn()=>require 'authgo-sealed://core/answer.php');
            // Same process, payload, license, identity and cache; only the Guard changes.
            $gb=Guard::start(['config'=>'authgo2.'.Client::b64(Json::encode($f->server->config)),
                'license'=>PayloadTests::LICENSE,'version'=>$f->payload->version,
                'sdk_options'=>['cache_dir'=>$f->dir,'fingerprint'=>PayloadTests::FP,'clock'=>fn()=>$f->server->now,'transport'=>$f->server->transport(...)]]);
            $gb->installSealed('core');self::check((require 'authgo-sealed://core/answer.php')===42);
            $ga->close();self::check((require 'authgo-sealed://core/later.php')===99); // Idempotent A close cannot remove B.
        }finally{if($gb)try{$gb->close();}catch(Error){}self::clean($f,$ga);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function foreignReplacement(): void
    {
        [$f,$g]=SealedTests::fixture(null,['core','other']);
        try {
            $g->installSealed('core');
            self::foreign(fn()=>self::denies(fn()=>$g->installSealed('other'),'PAYLOAD_INVALID'));
            self::check((require 'authgo-sealed://core/answer.php')===42);
            $g->installSealed('other');self::check((require 'authgo-sealed://other/answer.php')===42);
        }finally{self::clean($f,$g);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function foreignAfterLastClose(): void
    {
        [$a,$ga]=SealedTests::fixture();$b=$gb=null;
        try {
            $ga->installSealed('core');$ga->close();[$b,$gb]=SealedTests::fixture();
            self::foreign(fn()=>self::denies(fn()=>$gb->installSealed('core'),'PAYLOAD_INVALID'));
            $gb->installSealed('core');self::check((require 'authgo-sealed://core/answer.php')===42);
        }finally{if($b)self::clean($b,$gb);self::clean($a,$ga);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function foreignFirst(): void
    {
        [$f,$g]=SealedTests::fixture();
        try{self::foreign(fn()=>self::denies(fn()=>$g->installSealed('core'),'PAYLOAD_INVALID'));}
        finally{self::clean($f,$g);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function activeBuffer(): void
    {
        [$f,$g]=SealedTests::fixture();$h=null;
        try {
            $g->installSealed('core');$h=fopen('authgo-sealed://core/later.php','rb');self::check(fread($h,1)==='<');self::check(stream_get_meta_data($h)['unread_bytes']>0);
            $f->server->code='LICENSE_REVOKED';$f->server->now+=11;
            self::denies(fn()=>fstat($h),'LICENSE_REVOKED'); // Removal runs inside this handle's callback.
            self::check(is_resource($h)); // Do not fclose a stream while its native callback is on the stack.
            self::noBytes($h);self::denies(fn()=>require 'authgo-sealed://core/later.php');
        }finally{if(is_resource($h))fclose($h);self::clean($f,$g);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    private static function isolated(string $action): void
    {
        [$a,$ga]=SealedTests::fixture(null,['core','aux']);$b=$gb=$ha=$hb=null;
        try {
            $ga->installSealed('core');$ga->installSealed('aux');
            [$b,$gb]=SealedTests::fixture(null,['other','core']);$gb->installSealed('other');
            $ha=fopen('authgo-sealed://aux/later.php','rb');$hb=fopen('authgo-sealed://other/later.php','rb');
            self::check(fread($ha,1)==='<'&&fread($hb,1)==='<');
            self::denies(fn()=>$ga->installSealed('core'),'PAYLOAD_INVALID');
            self::denies(fn()=>$gb->installSealed('core'),'PAYLOAD_INVALID');
            self::denies(fn()=>$gb->installSealed('missing'),'PAYLOAD_INVALID');
            foreach(['missing.php','../answer.php','x//answer.php','answer.php?x'] as $path)self::denies(fn()=>fopen('authgo-sealed://core/'.$path,'rb'));
            foreach(['core','aux','other'] as $name)self::check((require 'authgo-sealed://'.$name.'/answer.php')===42);
            if($action==='close')$ga->close();
            else{$a->server->code='LICENSE_REVOKED';$a->server->now+=11;self::denies(fn()=>$ga->tick(),'LICENSE_REVOKED');}
            self::noBytes($ha);
            foreach(['core','aux'] as $name)self::denies(fn()=>require 'authgo-sealed://'.$name.'/answer.php');
            self::check(is_resource($hb)&&fread($hb,8192)==='?php return 99;');
            self::check((require 'authgo-sealed://other/answer.php')===42&&!$gb->done());
        }finally{foreach([$ha,$hb] as $h)if(is_resource($h))fclose($h);if($b)self::clean($b,$gb);self::clean($a,$ga);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function loadedCodeLimit(): void
    {
        [$f,$g]=SealedTests::fixture(SealedTests::tar([['limits.php','<?php function sealed_review_already_compiled(){return 42;}','0']]));
        try{$g->installSealed('core');require 'authgo-sealed://core/limits.php';$g->close();self::denies(fn()=>require 'authgo-sealed://core/limits.php');self::check(sealed_review_already_compiled()===42);}
        finally{self::clean($f,$g);putenv('AUTHGO_PAYLOAD_DIR');}
    }
    public static function run(): void
    {
        foreach(['A-close-B-reinstall'=>self::reinstall(...),'foreign-replacement-with-live-mount'=>self::foreignReplacement(...),'foreign-after-last-close'=>self::foreignAfterLastClose(...),'active-stat-callback-prefetch'=>self::activeBuffer(...),'multiple-mount-close-isolation'=>fn()=>self::isolated('close'),'multiple-mount-refusal-isolation'=>fn()=>self::isolated('refuse'),'already-compiled-code-limit'=>self::loadedCodeLimit(...)] as $name=>$test){$test();self::$passed++;echo 'sealed review '.$name." PASS\n";}
        $p=proc_open([PHP_BINARY,__FILE__,'foreign-first'],[0=>['pipe','r'],1=>['pipe','w'],2=>['pipe','w']],$pipes);
        self::check(is_resource($p));fclose($pipes[0]);$stdout=stream_get_contents($pipes[1]);$stderr=stream_get_contents($pipes[2]);fclose($pipes[1]);fclose($pipes[2]);self::check(proc_close($p)===0&&$stdout==="foreign first PASS\n"&&$stderr==='');
        self::$passed++;echo "sealed review foreign-first-fresh-process PASS\n";
        echo 'PHP sealed review tests: '.self::$passed." PASS\n";
    }
}
if(realpath($_SERVER['SCRIPT_FILENAME']??'')===__FILE__){if(($argv[1]??'')==='foreign-first'){SealedReviewTests::foreignFirst();echo "foreign first PASS\n";}elseif(($argv[1]??'')==='active-buffer')SealedReviewTests::activeBuffer();else SealedReviewTests::run();}
