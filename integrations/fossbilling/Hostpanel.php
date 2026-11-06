<?php
/**
 * HostPanel server manager for FOSSBilling.
 *
 * Install: copy this file to  <fossbilling>/library/Server/Manager/Hostpanel.php
 * Then:    System -> Hosting plans and servers -> New server -> Server manager "HostPanel".
 *          Hostname  = your panel address (panel.example.com, or the IP)
 *          Port      = 8443 (or 443 when you use the panel domain)
 *          Access hash (or Password) = a HostPanel API key with read + write access
 *
 * It talks to the HostPanel billing API (/api/v1, HostPanel 1.0.8 or newer): see docs/BILLING-API.md.
 * Written against the Server_Manager interface used by FOSSBilling's bundled managers.
 * Not exercised against a live FOSSBilling installation by the author: test on a staging order first.
 *
 * SPDX-License-Identifier: Apache-2.0
 */
class Server_Manager_Hostpanel extends Server_Manager
{
    public static function getForm(): array
    {
        return [
            'label' => 'HostPanel',
        ];
    }

    public function init()
    {
        if (empty($this->_config['host']) && empty($this->_config['ip'])) {
            throw new Server_Exception('The HostPanel server needs a hostname or IP address');
        }
        if ($this->apiKey() === '') {
            throw new Server_Exception('Put a HostPanel API key in the "Access hash" (or "Password") field of this server');
        }
    }

    public function getLoginUrl(Server_Account $account = null): string
    {
        return $this->baseUrl() . '/';
    }

    public function getResellerLoginUrl(Server_Account $account = null): string
    {
        return $this->getLoginUrl();
    }

    public function testConnection(): bool
    {
        $r = $this->request('GET', '/ping');
        return !empty($r['ok']);
    }

    public function synchronizeAccount(Server_Account $account): Server_Account
    {
        // Confirms the service exists; HostPanel does not report disk/bandwidth through this call.
        $this->request('GET', '/services/' . rawurlencode($this->domainOf($account)));
        return clone $account;
    }

    public function createAccount(Server_Account $account)
    {
        $package = $account->getPackage();
        $client = $account->getClient();
        $body = [
            'domain' => $this->domainOf($account),
            'username' => $account->getUsername(),
            'email' => $client->getEmail(),
            'password' => $account->getPassword(),
            'plan' => (string) $package->getName(),
            // Same value on every retry, so a repeated "create" does not create a second website.
            'externalId' => 'fb-' . substr(sha1($this->domainOf($account)), 0, 20),
            'limits' => [
                'diskMb' => $this->mbOrNull($package->getQuota()),
                'bandwidthMb' => $this->mbOrNull($package->getBandwidth()),
            ],
        ];
        $type = $package->getCustomValue('type');       // php (default), static, node, python, proxy
        if ($type) {
            $body['type'] = (string) $type;
        }
        $php = $package->getCustomValue('php_version');  // for example 8.4
        if ($php) {
            $body['php'] = (string) $php;
        }
        $this->request('POST', '/services', $body);
        return true;
    }

    public function suspendAccount(Server_Account $account)
    {
        $this->request('POST', '/services/' . rawurlencode($this->domainOf($account)) . '/suspend', ['reason' => 'Suspended by FOSSBilling']);
        return true;
    }

    public function unsuspendAccount(Server_Account $account): bool
    {
        $this->request('POST', '/services/' . rawurlencode($this->domainOf($account)) . '/unsuspend', new \stdClass());
        return true;
    }

    public function cancelAccount(Server_Account $account): bool
    {
        // A final backup is kept (HostPanel > Backups). Add ?skipBackup=1 here to delete without one.
        $this->request('DELETE', '/services/' . rawurlencode($this->domainOf($account)));
        // The client login is closed by HostPanel; removing the record works once the deletion has finished.
        try {
            $this->request('DELETE', '/clients/' . rawurlencode($account->getUsername()));
        } catch (Server_Exception $e) {
            // expected while the backup is still running: the closed login is harmless
        }
        return true;
    }

    public function changeAccountPackage(Server_Account $account, Server_Package $package): bool
    {
        $this->request('POST', '/services/' . rawurlencode($this->domainOf($account)) . '/plan', [
            'plan' => (string) $package->getName(),
            'limits' => [
                'diskMb' => $this->mbOrNull($package->getQuota()),
                'bandwidthMb' => $this->mbOrNull($package->getBandwidth()),
            ],
        ]);
        return true;
    }

    public function changeAccountUsername(Server_Account $account, string $newUsername): bool
    {
        throw new Server_Exception(':type: does not support :action:', [':type:' => 'HostPanel', ':action:' => __trans('username changes')]);
    }

    public function changeAccountDomain(Server_Account $account, string $newDomain): bool
    {
        throw new Server_Exception(':type: does not support :action:', [':type:' => 'HostPanel', ':action:' => __trans('changing the account domain')]);
    }

    public function changeAccountPassword(Server_Account $account, string $newPassword): bool
    {
        $this->request('POST', '/services/' . rawurlencode($this->domainOf($account)) . '/password', ['password' => $newPassword]);
        return true;
    }

    public function changeAccountIp(Server_Account $account, string $newIp): bool
    {
        throw new Server_Exception(':type: does not support :action:', [':type:' => 'HostPanel', ':action:' => __trans('changing the account IP')]);
    }

    /* ---------------- helpers ---------------- */

    private function domainOf(Server_Account $account): string
    {
        return strtolower(trim((string) $account->getDomain()));
    }

    private function apiKey(): string
    {
        $k = $this->_config['accesshash'] ?? '';
        if ($k === '' || $k === null) {
            $k = $this->_config['password'] ?? '';
        }
        return trim((string) $k);
    }

    private function baseUrl(): string
    {
        $host = $this->_config['host'] ?: $this->_config['ip'];
        $port = !empty($this->_config['port']) ? ':' . (int) $this->_config['port'] : '';
        return 'https://' . $host . $port;
    }

    /** FOSSBilling stores sizes as numbers (MB) or the word "unlimited". HostPanel wants whole MB or null. */
    private function mbOrNull($v): ?int
    {
        if ($v === null || $v === '' || !is_numeric($v) || (int) $v <= 0) {
            return null;
        }
        return (int) $v;
    }

    private function request(string $method, string $path, $body = null): array
    {
        $host = $this->_config['host'] ?: $this->_config['ip'];
        // A panel reached by IP has a self-signed certificate; a real hostname (panel domain) is verified.
        $verify = !filter_var($host, FILTER_VALIDATE_IP);
        $options = [
            'verify_peer' => $verify,
            'verify_host' => $verify,
            'timeout' => 60,
            'headers' => ['Authorization' => 'Bearer ' . $this->apiKey(), 'Accept' => 'application/json'],
        ];
        $client = $this->getHttpClient()->withOptions($options);
        $response = $client->request($method, $this->baseUrl() . '/api/v1' . $path, $body !== null ? ['json' => $body] : []);
        $status = $response->getStatusCode();
        $data = json_decode($response->getContent(false), true);
        if ($status >= 400) {
            $msg = is_array($data) && isset($data['error']['message']) ? $data['error']['message'] : 'HTTP ' . $status;
            $code = is_array($data) && isset($data['error']['code']) ? $data['error']['code'] : 'error';
            throw new Server_Exception('HostPanel: ' . $msg . ' (' . $code . ')');
        }
        return is_array($data) ? $data : [];
    }
}
