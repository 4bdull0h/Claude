<?php
// Simulated INTERNAL-only service (e.g. cloud metadata / internal admin API).
// Logs every hit so we can prove the relay reached it.
$log = __DIR__ . '/internal_hits.log';
$line = date('H:i:s') . ' HIT from ' . ($_SERVER['REMOTE_ADDR'] ?? '?')
      . ' UA=' . ($_SERVER['HTTP_USER_AGENT'] ?? '-')
      . ' PATH=' . ($_SERVER['REQUEST_URI'] ?? '-') . "\n";
file_put_contents($log, $line, FILE_APPEND);
header('Content-Type: text/plain');
header('Content-Length: 64');
echo "INTERNAL-SECRET: aws_key=AKIA_PRETEND_1234567890 (should never leak)\n";
