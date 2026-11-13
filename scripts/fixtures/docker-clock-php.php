<?php
require '/app/sdk/Client.php';require '/app/authgo-build.php';
$advance=false;
try{
    $g=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION,'sdk_options'=>['clock'=>fn()=>microtime(true)+($GLOBALS['advance']?72*3600+1:0)],'on_change'=>function($r,$e)use(&$advance){if($r){echo "clock agent: ".$r->status."\n";if($r->status==='grace')$advance=true;}if($e)echo "clock agent: ".$e->errorCode."\n";}]);
    echo "clock ready\n";
    while(!$g->done()){usleep(50000);try{$g->tick();}catch(AuthGo\Error){}}
    echo "clock stopped: ".$g->error()->errorCode."\n";
    try{$g->close();}catch(AuthGo\Error){}
}catch(AuthGo\Error $e){echo "clock error: ".$e->errorCode."\n";}
exit(AuthGo\EXIT_LICENSE);
