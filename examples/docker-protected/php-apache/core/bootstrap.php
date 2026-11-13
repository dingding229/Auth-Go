<?php
declare(strict_types=1);
return static function (AuthGo\Guard $guard): array {
    $guard->require();
    return ['marker'=>'AUTHGO_payload_PROTECTED_CORE', 'language'=>'php',
        'unique'=>'AUTHGO_payload_PHP_CORE', 'sapi'=>PHP_SAPI,
        'features'=>$guard->result()->features, 'is_trial'=>$guard->result()->isTrial,
        'status'=>$guard->result()->status, 'pid'=>getmypid()];
};
