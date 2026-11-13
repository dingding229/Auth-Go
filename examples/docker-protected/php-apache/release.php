<?php
declare(strict_types=1);
const CONFIG = null;
const VERSION = null;
require_once '/app/sdk/Client.php';
// All request workers have stopped before this short-lived CLI cleanup runs.
// Adopt the same stable instance once, then release: never reuse another PID's session.
try {
    $guard=AuthGo\start_guard(['config'=>CONFIG,'version'=>VERSION,
        'sdk_options'=>['transport'=>static function($url,$body,$headers,$timeout,$limit) {
            return AuthGo\Client::http($url,$body,$headers,min(2.0,$timeout),$limit);
        }]]);
    $guard->close();
} catch(AuthGo\Error $error) {
    fwrite(STDERR,'释放席位: '.$error->errorCode."\n");
    exit(AuthGo\EXIT_LICENSE);
}
