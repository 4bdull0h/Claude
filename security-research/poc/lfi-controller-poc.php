<?php
// Mirrors www/public/ajax/controller.php include logic exactly.
define('ROOT', __DIR__ . '/app');
$controller = $argv[1];                 // attacker-controlled $_POST['controller']
$target = ROOT . '/controllers/ajax/' . $controller . '.php';
echo "resolved include target: $target\n";
echo "realpath: " . var_export(realpath($target), true) . "\n";
if (!file_exists($target)) { echo "file_exists gate: FAIL (would say 'Bad controller')\n"; exit(1); }
echo "file_exists gate: PASS -> include_once fires\n";
include_once($target);                  // same call as controller.php:50
