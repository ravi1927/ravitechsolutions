<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('Referrer-Policy: same-origin');
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

function client_ip(): string {
  $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
  return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '0.0.0.0';
}

function rate_limit(string $dir, string $ip, int $max, int $window): bool {
  if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) return false;
  $file = $dir . '/' . hash('sha256', $ip) . '.json';
  $now = time();
  $hits = [];
  if (is_readable($file)) {
    $hits = json_decode((string)file_get_contents($file), true) ?: [];
  }
  $hits = array_values(array_filter($hits, fn($t) => is_int($t) && $t > $now - $window));
  if (count($hits) >= $max) return false;
  $hits[] = $now;
  file_put_contents($file, json_encode($hits), LOCK_EX);
  return true;
}

function send_mail_simple(string $to, string $from, string $subject, string $body): bool {
  $headers = [
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'From: ' . $from,
    'Reply-To: ' . $from,
    'X-Mailer: ravichandra-site',
  ];
  return @mail($to, '=?UTF-8?B?' . base64_encode($subject) . '?=', $body, implode("\r\n", $headers));
}

function send_mail_smtp(string $host, int $port, string $user, string $pass, string $to, string $from, string $subject, string $body, string $replyTo = ''): bool {
  $remote = ($port === 465 ? 'ssl://' : 'tcp://') . $host . ':' . $port;
  $fp = @stream_socket_client($remote, $errno, $errstr, 12, STREAM_CLIENT_CONNECT);
  if (!$fp) return false;
  stream_set_timeout($fp, 12);
  $read = function () use ($fp) { return (string)fgets($fp, 512); };
  $cmd = function (string $line) use ($fp) { fwrite($fp, $line . "\r\n"); };
  $read();
  $cmd('EHLO ravichandra.site');
  $ehlo = '';
  while ($line = $read()) {
    $ehlo .= $line;
    if (strlen($line) < 4 || $line[3] !== '-') break;
  }
  if ($port !== 465 && stripos($ehlo, 'STARTTLS') !== false) {
    $cmd('STARTTLS');
    $read();
    $ok = @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if (!$ok) { fclose($fp); return false; }
    $cmd('EHLO ravichandra.site');
    while ($line = $read()) { if (strlen($line) < 4 || $line[3] !== '-') break; }
  }
  $cmd('AUTH LOGIN');
  $read();
  $cmd(base64_encode($user));
  $read();
  $cmd(base64_encode($pass));
  $auth = $read();
  if (!str_starts_with($auth, '235')) { fclose($fp); return false; }
  $cmd('MAIL FROM:<' . $from . '>');
  $read();
  $cmd('RCPT TO:<' . $to . '>');
  $read();
  $cmd('DATA');
  $read();
  $reply = filter_var($replyTo, FILTER_VALIDATE_EMAIL) ? $replyTo : $from;
  $payload = 'From: ' . $from . "\r\n" .
    'To: ' . $to . "\r\n" .
    'Reply-To: ' . $reply . "\r\n" .
    'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=' . "\r\n" .
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" . $body . "\r\n.";
  $cmd($payload);
  $ok = str_starts_with($read(), '250');
  $cmd('QUIT');
  fclose($fp);
  return $ok;
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
  http_response_code(204);
  exit;
}

$root = dirname(__DIR__);
env_load($root . '/.env');

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'GET') {
  if (!hash_equals((string)($_GET['boot'] ?? ''), '1')) out(404, ['error' => 'Not found']);
  $token = bin2hex(random_bytes(16));
  $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
    || (($_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '') === 'https');
  setcookie('rc_csrf', $token, [
    'expires' => time() + 3600,
    'path' => '/',
    'secure' => $secure,
    'httponly' => true,
    'samesite' => 'Strict',
  ]);
  out(200, ['ok' => true, 'token' => $token]);
}

if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') out(405, ['error' => 'Method not allowed']);

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
$host = $_SERVER['HTTP_HOST'] ?? '';
$site = rtrim((string)(getenv('SITE_URL') ?: ''), '/');
if ($origin !== '') {
  $originHost = parse_url($origin, PHP_URL_HOST);
  if (!$originHost || strcasecmp((string)$originHost, (string)parse_url('https://' . $host, PHP_URL_HOST)) !== 0) {
    if ($site === '' || strcasecmp((string)$originHost, (string)parse_url($site, PHP_URL_HOST)) !== 0) {
      out(403, ['error' => 'Rejected']);
    }
  }
}

if (!rate_limit($root . '/data/rate', client_ip(), 5, 3600)) {
  out(429, ['error' => 'Please wait before sending another message.']);
}

$raw = file_get_contents('php://input') ?: '';
if (strlen($raw) > 8000) out(413, ['error' => 'Message is too long.']);
$input = json_decode($raw, true);
if (!is_array($input)) out(422, ['error' => 'Invalid request.']);

if (trim((string)($input['company_url'] ?? '')) !== '') out(200, ['ok' => true]); // honeypot

$cookie = (string)($_COOKIE['rc_csrf'] ?? '');
$header = (string)($_SERVER['HTTP_X_CSRF_TOKEN'] ?? '');
$posted = (string)($input['token'] ?? '');
if ($cookie === '' || $header === '' || $posted === '' || !hash_equals($cookie, $header) || !hash_equals($cookie, $posted)) {
  out(403, ['error' => 'Refresh the page and try again.']);
}

$name = trim(preg_replace('/[\x00-\x1F\x7F]/', '', (string)($input['name'] ?? '')));
$email = strtolower(trim((string)($input['email'] ?? '')));
$org = trim(preg_replace('/[\x00-\x1F\x7F]/', '', (string)($input['org'] ?? '')));
$message = trim(preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/', '', (string)($input['message'] ?? '')));

if (strlen($name) < 2 || strlen($name) > 80) out(422, ['error' => 'Enter your name.']);
if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 120) out(422, ['error' => 'Enter a valid email.']);
if (strlen($org) > 120) out(422, ['error' => 'Company name is too long.']);
if (strlen($message) < 10 || strlen($message) > 4000) out(422, ['error' => 'Enter a message of at least 10 characters.']);

$to = getenv('MAIL_TO') ?: '';
if ($to === '' || !filter_var($to, FILTER_VALIDATE_EMAIL)) out(500, ['error' => 'Inbox is not configured.']);
$smtpUser = (string)(getenv('SMTP_USER') ?: '');
$fromDefault = $smtpUser !== '' ? $smtpUser : ((string)(getenv('MAIL_FROM') ?: ('noreply@' . preg_replace('/^www\./', '', $host ?: 'localhost'))));
$subject = 'Ravi Tech Solutions enquiry from ' . $name;
$body = "Name: $name\nEmail: $email\nCompany: " . ($org !== '' ? $org : '—') . "\nIP: " . client_ip() . "\nTime: " . gmdate('c') . "\n\n$message\n";

$inbox = $root . '/data/inbox.jsonl';
$record = json_encode([
  'at' => gmdate('c'),
  'name' => $name,
  'email' => $email,
  'org' => $org,
  'message' => $message,
  'ip' => hash('sha256', client_ip()),
], JSON_UNESCAPED_UNICODE) . "\n";
@file_put_contents($inbox, $record, FILE_APPEND | LOCK_EX);

$sent = false;
$smtpHost = getenv('SMTP_HOST') ?: '';
if ($smtpHost && getenv('SMTP_USER') && getenv('SMTP_PASS')) {
  $sent = send_mail_smtp(
    $smtpHost,
    (int)(getenv('SMTP_PORT') ?: 587),
    $smtpUser,
    (string)getenv('SMTP_PASS'),
    $to,
    $fromDefault,
    $subject,
    $body,
    $email
  );
}
if (!$sent) $sent = send_mail_simple($to, $fromDefault, $subject, $body);
if (!$sent) out(500, ['error' => 'Saved locally, but email could not be sent. Check SMTP on the server.']);

out(200, ['ok' => true]);
