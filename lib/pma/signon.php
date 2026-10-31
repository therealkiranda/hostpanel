<?php
// HostPanel -> phpMyAdmin single sign-on. The panel (root) writes a one-time ticket file that holds the credentials of
// a MariaDB account restricted to ONE website's databases; this script consumes the ticket and hands over to phpMyAdmin.
// No credential ever travels in a URL: the URL only carries the random ticket id, which works once for 60 seconds.
declare(strict_types=1);
const TICKETS = '/opt/hostpanel/pma/tickets/';
function deny(): void { http_response_code(403); header('Content-Type: text/plain; charset=utf-8'); echo "This link has expired. Open phpMyAdmin again from HostPanel.\n"; exit; }
$t = $_GET['t'] ?? '';
if (!is_string($t) || !preg_match('/^[a-f0-9]{48}$/', $t)) deny();
$file = TICKETS . $t;
$raw = @file_get_contents($file);
@unlink($file);                       // single use, even when the ticket turns out to be invalid
if ($raw === false) deny();
$j = json_decode($raw, true);
if (!is_array($j) || !isset($j['u'], $j['p'], $j['exp']) || (int)$j['exp'] < time() || !preg_match('/^[a-z][a-z0-9_]{2,40}$/', (string)$j['u'])) deny();
session_name('HPPMA');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Lax']);
session_start();
$_SESSION = [];
$_SESSION['PMA_single_signon_user'] = (string)$j['u'];
$_SESSION['PMA_single_signon_password'] = (string)$j['p'];
$_SESSION['PMA_single_signon_host'] = 'localhost';
session_write_close();
header('Cache-Control: no-store');
header('Location: /index.php', true, 303);
