<?php
// Minimal shim for the one Laravel interface PublicHttpUrl implements, so we can
// exercise the REAL rule file unmodified.
namespace Illuminate\Contracts\Validation { interface ValidationRule { public function validate(string $attribute, mixed $value, \Closure $fail): void; } }
namespace {
    require $argv[1];   // the real app/Rules/PublicHttpUrl.php
    $rule = new \App\Rules\PublicHttpUrl();
    $cases = [
        'http://8.8.8.8/product/1', 'https://1.1.1.1/x',
        'http://127.0.0.1:9000/secret',             // loopback
        'http://localhost/secret',                  // localhost
        'http://169.254.169.254/latest/meta-data/', // cloud metadata
        'http://[::1]/secret',                      // ipv6 loopback
    ];
    foreach ($cases as $u) {
        $failed = null;
        $rule->validate('url', $u, function($m) use (&$failed){ $failed = $m; });
        printf("%-45s => %s\n", $u, $failed ? "BLOCKED ($failed)" : "PASSES validator");
    }
}
