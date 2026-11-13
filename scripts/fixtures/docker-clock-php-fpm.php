<?php
// TEST IMAGE ONLY: marker under /tmp never exists in the production router.
require '/app/sdk/Client.php';require '/app/authgo-build.php';
if(($_SERVER['REQUEST_URI']??'')==='/__test/session'){
    $client=new AuthGo\Client(CONFIG);$method=new ReflectionMethod($client,'body');
    header('Content-Type: application/json');echo json_encode(['has_session'=>array_key_exists('instance_session',$method->invoke($client))]);return;
}
if(($_SERVER['REQUEST_URI']??'')==='/__test/advance'){
    file_put_contents('/tmp/authgo-clock','1');echo 'advanced';return;
}
try{
    $guard=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION,'sdk_options'=>['clock'=>fn()=>microtime(true)+(is_file('/tmp/authgo-clock')?72*3600+1:0)]]);
    $guard->require();header('Content-Type: application/json');echo json_encode(['status'=>$guard->result()->status,'pid'=>getmypid()]);
}catch(AuthGo\Error $e){http_response_code(503);header('Content-Type: application/json');echo json_encode(['code'=>$e->errorCode]);}
