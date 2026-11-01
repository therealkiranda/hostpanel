<?php
// HostPanel -> phpMyAdmin single sign-on. The panel (root) writes a ticket file that holds the credentials of a MariaDB
// account restricted to ONE website's databases; this script turns it into a phpMyAdmin session.
// No credential travels in a URL: the URL only carries the random ticket id. The ticket works for 10 minutes, but only in
// the browser that used it first (a binding cookie), so reloading the page, switching Chrome to "Desktop site" or opening
// the link again does not show "expired", while a copied link is useless to anyone else.
declare(strict_types=1);
const TICKETS = '/opt/hostpanel/pma/tickets/';
session_name('HPPMA');
session_set_cookie_params(['lifetime' => 28800, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
session_start();
function go(): void { session_write_close(); header('Cache-Control: no-store'); header('Location: /index.php', true, 303); exit; }
function deny(): void { http_response_code(403); header('Content-Type: text/plain; charset=utf-8'); echo "This link has expired. Open phpMyAdmin again from HostPanel.\n"; exit; }
function already(): void { if (!empty($_SESSION['PMA_single_signon_user'])) go(); deny(); } // a signed-in browser just continues
$t = $_GET['t'] ?? '';
if (!is_string($t) || !preg_match('/^[a-f0-9]{48}$/', $t)) already();
$file = TICKETS . $t;
$raw = @file_get_contents($file);
if ($raw === false) already();
$j = json_decode($raw, true);
if (!is_array($j) || !isset($j['u'], $j['p'], $j['exp']) || (int)$j['exp'] < time() || !preg_match('/^[a-z][a-z0-9_]{2,40}$/', (string)$j['u'])) { @unlink($file); already(); }
if (isset($j['b'])) { // used before: only the same browser may use it again
    $c = $_COOKIE['HPPMAB'] ?? '';
    if (!is_string($c) || $c === '' || !hash_equals((string)$j['b'], hash('sha256', $c))) already();
} else {
    $c = bin2hex(random_bytes(24));
    $j['b'] = hash('sha256', $c);
    @file_put_contents($file, json_encode($j), LOCK_EX);
    setcookie('HPPMAB', $c, ['expires' => time() + 900, 'path' => '/hp-signon', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
}
$_SESSION = [];
$_SESSION['PMA_single_signon_user'] = (string)$j['u'];
$_SESSION['PMA_single_signon_password'] = (string)$j['p'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
go();
