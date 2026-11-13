<?php
declare(strict_types=1);
require '/app/sdk/Client.php';
require '/app/authgo-build.php';
try {
    $guard=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION]);
    $guard->require();
    if($guard->result()->isTrial)error_log("当前为试用");
    header('Content-Type: application/json; charset=utf-8');
    echo AuthGo\Json::encode(['features'=>$guard->result()->features,'is_trial'=>$guard->result()->isTrial,'status'=>$guard->result()->status,'pid'=>getmypid()]);
    // Deliberately no close per request: a container owns one seat, not a request.
} catch(AuthGo\Error $error) {
    http_response_code(503);header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['code'=>$error->errorCode],JSON_THROW_ON_ERROR);
}
