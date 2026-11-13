<?php
declare(strict_types=1);
// Build-time generator only. Final PHP constants live in the public program itself.
foreach (glob('/src/example/*.php') as $file) {
    if (basename($file)==='build.php') continue;
    $source=file_get_contents($file);
    $source=str_replace('const CONFIG = null;', 'const CONFIG = '.var_export(getenv('AUTHGO_CONFIG'),true).';', $source);
    $source=str_replace('const VERSION = null;', 'const VERSION = '.var_export(getenv('VERSION'),true).';', $source);
    file_put_contents('/public/'.basename($file),$source);
}
