<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');

function out(int $code, array $body): never {
  http_response_code($code);
  echo json_encode($body, JSON_UNESCAPED_UNICODE);
  exit;
}

function env_load(string $file): void {
  if (!is_readable($file)) return;
  foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) ?: [] as $line) {
    $line = trim($line);
    if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) continue;
    [$k, $v] = explode('=', $line, 2);
    $k = trim($k);
    $v = trim($v, " \t\"'");
    if ($k !== '' && getenv($k) === false) {
      putenv("$k=$v");
      $_ENV[$k] = $v;
    }
  }
}

function is_bot(string $ua): bool {
  if ($ua === '') return true;
  return (bool)preg_match('/bot|crawl|spider|slurp|curl|wget|python-requests|httpclient|monitor|uptime/i', $ua);
}

$root = dirname(__DIR__);
env_load($root . '/.env');
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'GET') out(405, ['error' => 'Method not allowed']);

$ua = (string)($_SERVER['HTTP_USER_AGENT'] ?? '');
$ip = (string)($_SERVER['REMOTE_ADDR'] ?? '0.0.0.0');
if (!filter_var($ip, FILTER_VALIDATE_IP)) $ip = '0.0.0.0';
$today = gmdate('Y-m-d');
$hash = hash('sha256', $ip . '|' . $today . '|rc-visit');
$life = hash('sha256', $ip . '|rc-life');
$file = $root . '/data/stats.json';

$fp = fopen($file, 'c+');
if (!$fp) out(500, ['error' => 'Stats unavailable']);
flock($fp, LOCK_EX);
$raw = stream_get_contents($fp);
$stats = json_decode($raw ?: '', true);
if (!is_array($stats)) $stats = ['totalUnique' => 0, 'totalViews' => 0, 'seen' => [], 'days' => []];
if (!isset($stats['days']) || !is_array($stats['days'])) $stats['days'] = [];
if (!isset($stats['seen']) || !is_array($stats['seen'])) $stats['seen'] = [];

$record = !isset($_GET['report']);
if ($record && !is_bot($ua)) {
  $stats['totalViews'] = (int)($stats['totalViews'] ?? 0) + 1;
  if (!isset($stats['days'][$today])) $stats['days'][$today] = ['views' => 0, 'uniques' => 0, 'hashes' => []];
  $stats['days'][$today]['views']++;
  if (!in_array($hash, $stats['days'][$today]['hashes'], true)) {
    $stats['days'][$today]['hashes'][] = $hash;
    $stats['days'][$today]['uniques']++;
  }
  if (!isset($stats['seen'][$life])) {
    $stats['seen'][$life] = $today;
    $stats['totalUnique'] = (int)($stats['totalUnique'] ?? 0) + 1;
  }
  if (count($stats['days']) > 400) {
    ksort($stats['days']);
    $stats['days'] = array_slice($stats['days'], -366, null, true);
  }
  foreach ($stats['days'] as $d => $row) {
    if ($d !== $today) unset($stats['days'][$d]['hashes']);
  }
  rewind($fp);
  ftruncate($fp, 0);
  fwrite($fp, json_encode($stats, JSON_UNESCAPED_UNICODE));
}

$todayRow = $stats['days'][$today] ?? ['views' => 0, 'uniques' => 0];
$public = [
  'ok' => true,
  'today' => (int)($todayRow['uniques'] ?? 0),
  'total' => (int)($stats['totalUnique'] ?? 0),
  'todayViews' => (int)($todayRow['views'] ?? 0),
  'totalViews' => (int)($stats['totalViews'] ?? 0),
  'date' => $today,
];

$key = (string)(getenv('STATS_KEY') ?: '');
$given = (string)($_GET['key'] ?? $_SERVER['HTTP_X_STATS_KEY'] ?? '');
if ($key !== '' && hash_equals($key, $given)) {
  $days = [];
  $copy = $stats['days'];
  krsort($copy);
  $i = 0;
  foreach ($copy as $d => $row) {
    if ($i++ >= 14) break;
    $days[] = ['date' => $d, 'visitors' => (int)($row['uniques'] ?? 0), 'views' => (int)($row['views'] ?? 0)];
  }
  $public['days'] = $days;
}

flock($fp, LOCK_UN);
fclose($fp);
out(200, $public);
