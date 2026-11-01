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
    // Gmail App Passwords are often pasted with spaces (abcd efgh ...); SMTP needs no whitespace.
    if ($k === 'SMTP_PASS') {
      $v = preg_replace('/\s+/u', '', $v) ?? $v;
    }
    if ($k !== '' && getenv($k) === false) {
      putenv("$k=$v");
      $_ENV[$k] = $v;
    }
  }
}

/** Private mail diagnostic log under data/ (web-denied). Never write secrets. */
function mail_log(string $root, string $stage, string $detail = ''): void {
  $dir = $root . '/data';
  if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) return;
  $line = gmdate('c') . "\t" . $stage;
  if ($detail !== '') {
    $safe = preg_replace('/[\x00-\x1F\x7F]+/', ' ', $detail) ?? $detail;
    // Redact anything that looks like a base64 AUTH payload or password-ish token.
    $safe = preg_replace('/\b[A-Za-z0-9+\/=]{20,}\b/', '[redacted]', $safe) ?? $safe;
    $line .= "\t" . substr($safe, 0, 240);
  }
  @file_put_contents($dir . '/mail.log', $line . "\n", FILE_APPEND | LOCK_EX);
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

function send_mail_smtp(string $root, string $host, int $port, string $user, string $pass, string $to, string $from, string $subject, string $body, string $replyTo = ''): bool {
  // Defensive: strip whitespace even if SMTP_PASS came from the process environment.
  $pass = preg_replace('/\s+/u', '', $pass) ?? $pass;
  $remote = ($port === 465 ? 'ssl://' : 'tcp://') . $host . ':' . $port;
  $fp = @stream_socket_client($remote, $errno, $errstr, 12, STREAM_CLIENT_CONNECT);
  if (!$fp) {
    mail_log($root, 'connect', "fail errno=$errno err=" . substr($errstr, 0, 120) . " remote=$host:$port");
    return false;
  }
  stream_set_timeout($fp, 12);
  $read = function () use ($fp) { return (string)fgets($fp, 512); };
  $cmd = function (string $line) use ($fp) { fwrite($fp, $line . "\r\n"); };
  $banner = $read();
  if ($banner === '' || !str_starts_with($banner, '220')) {
    mail_log($root, 'banner', trim($banner) !== '' ? trim($banner) : 'empty');
    fclose($fp);
    return false;
  }
  $ehloHost = preg_replace('/[^a-zA-Z0-9.-]/', '', (string)(parse_url((string)(getenv('SITE_URL') ?: ''), PHP_URL_HOST) ?: 'localhost')) ?: 'localhost';
  $cmd('EHLO ' . $ehloHost);
  $ehlo = '';
  while ($line = $read()) {
    $ehlo .= $line;
    if (strlen($line) < 4 || $line[3] !== '-') break;
  }
  if ($port !== 465 && stripos($ehlo, 'STARTTLS') !== false) {
    $cmd('STARTTLS');
    $tlsResp = $read();
    if (!str_starts_with($tlsResp, '220')) {
      mail_log($root, 'starttls', trim($tlsResp));
      fclose($fp);
      return false;
    }
    $ok = @stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT);
    if (!$ok) {
      mail_log($root, 'tls', 'stream_socket_enable_crypto failed');
      fclose($fp);
      return false;
    }
    $cmd('EHLO ' . $ehloHost);
    while ($line = $read()) { if (strlen($line) < 4 || $line[3] !== '-') break; }
  }
  $cmd('AUTH LOGIN');
  $authPrompt = $read();
  if (!str_starts_with($authPrompt, '334')) {
    mail_log($root, 'auth-start', trim($authPrompt));
    fclose($fp);
    return false;
  }
  $cmd(base64_encode($user));
  $userPrompt = $read();
  if (!str_starts_with($userPrompt, '334')) {
    mail_log($root, 'auth-user', trim($userPrompt));
    fclose($fp);
    return false;
  }
  $cmd(base64_encode($pass));
  $auth = $read();
  if (!str_starts_with($auth, '235')) {
    // Log SMTP reply code/text only — never user/pass.
    mail_log($root, 'auth', trim($auth) . ' user_len=' . strlen($user) . ' pass_len=' . strlen($pass));
    fclose($fp);
    return false;
  }
  $cmd('MAIL FROM:<' . $from . '>');
  $mailFrom = $read();
  if (!str_starts_with($mailFrom, '250')) {
    mail_log($root, 'mail-from', trim($mailFrom));
    fclose($fp);
    return false;
  }
  $cmd('RCPT TO:<' . $to . '>');
  $rcpt = $read();
  if (!str_starts_with($rcpt, '250')) {
    mail_log($root, 'rcpt', trim($rcpt));
    fclose($fp);
    return false;
  }
  $cmd('DATA');
  $data = $read();
  if (!str_starts_with($data, '354')) {
    mail_log($root, 'data', trim($data));
    fclose($fp);
    return false;
  }
  $reply = filter_var($replyTo, FILTER_VALIDATE_EMAIL) ? $replyTo : $from;
  $payload = 'From: ' . $from . "\r\n" .
    'To: ' . $to . "\r\n" .
    'Reply-To: ' . $reply . "\r\n" .
    'Subject: =?UTF-8?B?' . base64_encode($subject) . '?=' . "\r\n" .
    "MIME-Version: 1.0\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n" . $body . "\r\n.";
  $cmd($payload);
  $final = $read();
  $ok = str_starts_with($final, '250');
  if (!$ok) mail_log($root, 'send', trim($final));
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
$smtpPass = preg_replace('/\s+/u', '', (string)(getenv('SMTP_PASS') ?: '')) ?? '';
if ($smtpHost && $smtpUser !== '' && $smtpPass !== '') {
  $sent = send_mail_smtp(
    $root,
    $smtpHost,
    (int)(getenv('SMTP_PORT') ?: 587),
    $smtpUser,
    $smtpPass,
    $to,
    $fromDefault,
    $subject,
    $body,
    $email
  );
  if (!$sent) mail_log($root, 'smtp-failed', 'falling back to mail()');
} else {
  mail_log($root, 'smtp-skip', 'missing SMTP_HOST/USER/PASS');
}
if (!$sent) $sent = send_mail_simple($to, $fromDefault, $subject, $body);
if (!$sent) {
  mail_log($root, 'mail-failed', 'SMTP and mail() both failed');
  out(500, ['error' => 'Saved locally, but email could not be sent. Check SMTP on the server.']);
}

out(200, ['ok' => true]);
