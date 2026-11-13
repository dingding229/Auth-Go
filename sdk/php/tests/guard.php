<?php
require __DIR__.'/../src/Client.php';
use AuthGo\{Client as C,Json as J,Error as E};
function assertGuard(bool $ok): void {if(!$ok)throw new Exception('guard assertion');}
function expectGuard(callable $call,string $code): void {try{$call();throw new Exception('expected failure');}catch(E $e){assertGuard($e->errorCode===$code);}}
foreach (['cli'=>true,'fpm-fcgi'=>false,'apache2handler'=>false,'cgi-fcgi'=>false,'litespeed'=>false,'cli-server'=>false,'unknown'=>false] as $sapi=>$persistent) {
    assertGuard(AuthGo\isPersistentRuntime($sapi)===$persistent);
}
assertGuard(AuthGo\isPersistentRuntime() === (PHP_SAPI === 'cli'));
echo "PHP SAPI CLI/request classification PASS\n";
$v=json_decode(file_get_contents(__DIR__.'/../../vectors/v2.json'),true);
$sign=sodium_crypto_sign_secretkey(sodium_crypto_sign_seed_keypair(hex2bin($v['ed25519_seed_hex'])));
$config='authgo2.'.C::b64(J::encode(['url'=>'http://127.0.0.1:1','app_key'=>'app_test','app_secret'=>'test','gateway_key'=>$v['gateway_public'],'public_key'=>base64_encode(C::decode($v['ed25519_public']))]));
$now=1793923200;$calls=0;$code='OK';$offline=false;$ops=[];$timeouts=[];
$transport=function($url,$body,$headers,$timeout)use(&$now,&$calls,&$code,&$offline,&$ops,&$timeouts,$v,$sign){
    $calls++;$timeouts[]=$timeout;
    if($offline)throw new E('SDK_NETWORK_ERROR');
    $p=J::parse($body);$aad="authgo-gateway-v2\0".$p['k']."\0".$p['e'];$salt=hash('sha256',$aad,true);
    $shared=sodium_crypto_scalarmult(hex2bin($v['gateway_private_hex']),C::decode($p['e']));
    $inner=J::parse(C::unpad(C::open(C::hkdf($shared,$salt,'authgo/v2/request'),C::decode($p['n']),C::decode($p['c']),$aad)));
    $op=$inner['op'];$ops[]=$op;$req=$inner['body'];
    $d=['request_nonce'=>$inner['nonce']];
    if($op==='release-seat')$d['released']=true;
    else {
        $base=J::parse(C::decode(explode('.',$v['ticket'])[0]));
        $base['app_key']='app_test';$base['challenge']=$req['challenge'];$base['device_hash']=C::hash(str_repeat('a',64));
        $base['issued_at']=gmdate('Y-m-d\TH:i:s\Z',$now);$base['grace_until']=gmdate('Y-m-d\TH:i:s\Z',$now+4);
        $base['expires_at']=null;$base['next_check_in']=1;$base['floating']=true;$base['lease_expires_at']=gmdate('Y-m-d\TH:i:s\Z',$now+2);
        $base['features']=['export'=>true,'nested'=>['n'=>1]];$base['unlock_hash']=C::hash(str_repeat('u',32));
        $raw=J::encode($base);$ticket=C::b64($raw).'.'.C::b64(sodium_crypto_sign_detached("authgo-ticket-v2\0".$raw,$sign));
        $d+=['license_id'=>$base['license_id'],'next_check_in'=>1,'heartbeat_interval'=>1,'ticket'=>$ticket,'unlock_seed'=>C::b64(str_repeat('u',32))];
        if($op==='activate')$d['activation_token']='act_'.str_repeat('a',43);
    }
    $env=['code'=>$code,'data'=>$d,'ts'=>$now,'nonce'=>$inner['nonce']];
    $env['signature']=base64_encode(sodium_crypto_sign_detached(J::encode(['code'=>$code,'data'=>$d,'ts'=>$now]),$sign));
    $nonce=random_bytes(12);$ci=C::seal(C::hkdf($shared,$salt,'authgo/v2/response'),$nonce,C::pad(J::encode($env)),$aad."\0".C::hash($p['n'].'.'.$p['c']));
    return [200,[],J::encode(['n'=>C::b64($nonce),'c'=>C::b64($ci)])];
};
$opts=['config'=>$config,'license'=>'AUTH-23456-789AB-CDEFG-HJKLT','sdk_options'=>['fingerprint'=>str_repeat('a',64),'cache_dir'=>'','clock'=>function()use(&$now){return $now;},'transport'=>$transport]];
expectGuard(fn()=>AuthGo\start_guard([]),'SDK_INVALID_CONFIG');$before=$calls;
expectGuard(fn()=>AuthGo\start_guard(array_replace($opts,['license'=>'abc'])),'INVALID_LICENSE_KEY');assertGuard($calls===$before);
$code='LICENSE_REVOKED';expectGuard(fn()=>AuthGo\start_guard($opts),'LICENSE_REVOKED');$code='OK';
$changed=[];$opts['on_change']=function($r,$e)use(&$changed){$changed[]=$e?$e->errorCode:$r->status;};
$g=AuthGo\start_guard($opts);assertGuard(!$g->done());$before=$calls;$g->require('export');assertGuard($calls===$before);
$r=$g->result();$r->features['nested']['n']=99;assertGuard(J::num($g->result()->features['nested']['n'])===1.0);
expectGuard(fn()=>$g->require('missing'),'INVALID_POLICY');
assertGuard(!isset($g->result()->data['heartbeat_interval'])&&$g->result()->heartbeatInterval===1.0);
$now++;$g->tick();assertGuard(in_array('heartbeat',$ops,true));
$offline=true;$now++;$g->tick();assertGuard($g->result()->status==='grace'&&!$g->done());$g->require('export');
$now+=5;expectGuard(fn()=>$g->tick(),'SDK_GRACE_EXPIRED');assertGuard($g->done());expectGuard(fn()=>$g->require(),'SDK_GRACE_EXPIRED');
expectGuard(fn()=>$g->close(),'SDK_NETWORK_ERROR');assertGuard(end($timeouts)===5.0||end($timeouts)===5);
$offline=false;$g=AuthGo\start_guard($opts);$g->close();$before=$calls;$g->close();assertGuard($calls===$before);expectGuard(fn()=>$g->require(),'SDK_NOT_ACTIVATED');
assertGuard(AuthGo\EXIT_LICENSE===77);
echo "PHP Guard initial/local/snapshot/heartbeat/grace/final/close PASS\n";
