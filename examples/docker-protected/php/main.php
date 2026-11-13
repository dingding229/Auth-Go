<?php
declare(strict_types=1);
const CONFIG = null;
const VERSION = null;
// Only the business example enables pcntl; the SDK never registers signals.
final class BusinessStopped extends RuntimeException {}
$stopping=false;
pcntl_async_signals(true);
pcntl_signal(SIGTERM,function()use(&$stopping){if(!$stopping){$stopping=true;throw new BusinessStopped();}}, false);
pcntl_signal(SIGINT,function()use(&$stopping){if(!$stopping){$stopping=true;throw new BusinessStopped();}}, false);

function change($r,$e): void {
    if($e)fwrite(STDERR,"授权检查: ".$e->errorCode."\n");
    if($r){echo "授权状态: ".$r->status."\n";if($r->cacheWarning)echo "缓存提示: ".$r->cacheWarning."\n";}
}
function run(array $args,bool &$stopping): int {
    try{$guard=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION,'on_change'=>'change','sdk_options'=>['transport'=>static function($url,$body,$headers,$timeout,$limit){return AuthGo\Client::http($url,$body,$headers,min(2.0,$timeout),$limit);}]]);}
    catch(AuthGo\Error $e){fwrite(STDERR,"授权验证失败: ".$e->errorCode."\n");return $stopping?0:AuthGo\EXIT_LICENSE;}
    try { $guard->installSealed('core'); $core = require 'authgo-sealed://core/bootstrap.php'; }
    catch(AuthGo\Error $e) { try{$guard->close();}catch(AuthGo\Error){} fwrite(STDERR,"授权验证失败: ".$e->errorCode."\n"); return AuthGo\EXIT_LICENSE; }
    if($guard->result()->isTrial)echo "当前为试用\n";
    change($guard->result(),null);
    $listen='0.0.0.0:8080';foreach($args as $i=>$value)if($value==='-listen')$listen=$args[$i+1];
    $server=stream_socket_server('tcp://'.$listen,$errno,$message);
    if(!$server){try{$guard->close();}catch(AuthGo\Error){}return 1;}
    stream_set_blocking($server,false);echo "HTTP已启动 version=".VERSION."\n";
    try{
        while(!$stopping){
            try{$guard->tick();}catch(AuthGo\Error $e){fwrite(STDERR,"授权已失效: ".$e->errorCode."\n");return $stopping?0:AuthGo\EXIT_LICENSE;}
            $read=[$server];$write=$except=[];
            if(@stream_select($read,$write,$except,0,50000)>0){
                $connection=@stream_socket_accept($server,0);
                if($connection){
                    stream_set_timeout($connection,0,200000);@fread($connection,1024);
                    try{$guard->require();$body=AuthGo\Json::encode($core($guard));$response="HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ".strlen($body)."\r\nConnection: close\r\n\r\n".$body;}
                    catch(AuthGo\Error $e){$response="HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n".$e->errorCode;}
                    @fwrite($connection,$response);fclose($connection);
                }
            }
        }
        return 0;
    }finally{fclose($server);try{$guard->close();}catch(AuthGo\Error $e){fwrite(STDERR,"释放席位: ".$e->errorCode."\n");}}
}
try {require '/app/sdk/Client.php';exit(run($argv,$stopping));}
catch(BusinessStopped){exit(0);}
