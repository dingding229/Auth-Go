<?php
declare(strict_types=1);
const CONFIG = null;
const VERSION = null;
require_once '/app/sdk/Client.php';
try {
    $guard=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION]);
    $guard->installSealed('core');
    $core=require 'authgo-sealed://core/bootstrap.php';
    header('Content-Type: application/json; charset=utf-8');
    echo AuthGo\Json::encode($core($guard));
    // Do not release a container's seat after each request. Destruction clears memory.
} catch(AuthGo\Error $error) {
    http_response_code(503);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['code'=>$error->errorCode],JSON_THROW_ON_ERROR);
}
