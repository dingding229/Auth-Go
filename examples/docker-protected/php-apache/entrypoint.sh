#!/bin/sh
# This shell only supervises the business SAPI and performs one shutdown cleanup.
# No licensing sidecar, periodic CLI Guard, runtime config file, or extra trust root.
set -u
stopping=0
child=
stop() {
    stopping=1
    if [ -n "$child" ]; then kill -WINCH "$child" 2>/dev/null || :; fi
}
trap stop TERM INT
"$@" &
child=$!
if [ "$stopping" = 1 ]; then stop; fi
# Probe only the local listener, without injecting trust config or license switches.
if php -r 'for($i=0;$i<100;$i++){$s=@stream_socket_client("tcp://127.0.0.1:8080",$e,$m,.05);if($s){fclose($s);exit(0);}usleep(50000);}exit(1);'; then
    echo 'HTTP已启动 php-apache :8080'
fi
status=0
while :; do
    wait "$child"; status=$?
    kill -0 "$child" 2>/dev/null || break
done
trap '' TERM INT
# Guard.close has a five-second request budget; bound the entire final takeover too.
timeout 8 php /app/release.php || echo '停止释放未完成（服务器不可达或授权已拒绝）' >&2
if [ "$stopping" = 1 ]; then exit 0; fi
exit "$status"
