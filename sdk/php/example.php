<?php
require __DIR__ . "/src/Client.php";
const AUTH_CONFIG = "authgo2.请在构建时替换为后台接入配置";
$client = new AuthGo\Client(AUTH_CONFIG);
$result = $client->check(getenv("AUTHGO_LICENSE"));
echo $result->status, PHP_EOL;
