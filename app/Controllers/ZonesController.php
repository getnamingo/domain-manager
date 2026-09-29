<?php

namespace App\Controllers;

use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Container\ContainerInterface;
use League\ISO3166\ISO3166;
use Namingo\Cardo\DNS\Service as CardoService;
use NetDNS2\Resolver as DNSResolver;
use Utopia\DNS\Client;
use Utopia\DNS\Message;
use Utopia\DNS\Message\Question;
use Utopia\DNS\Message\Record;

class ZonesController extends Controller
{
    private function ownedZone(string $domainName): ?array
    {
        $db = $this->container->get('db');
        $domain = $db->selectRow(
            'SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId, config
             FROM zones WHERE domain_name = ? LIMIT 1',
            [$domainName]
        );

        if (!$domain) {
            return null;
        }

        if ((int)$domain['client_id'] !== (int)($_SESSION['auth_user_id'] ?? 0)
            && (int)($_SESSION['auth_roles'] ?? -1) !== 0) {
            return null;
        }

        return $domain;
    }

    private function cardoConfig(array $domain): array
    {
        $persisted = json_decode((string)($domain['config'] ?? ''), true);
        if (!is_array($persisted) || empty($persisted['provider'])) {
            throw new \RuntimeException('Stored DNS provider configuration is invalid.');
        }

        return buildDnsProviderConfig(
            (string)$persisted['provider'],
            (string)$domain['domain_name'],
            $persisted
        );
    }

    private function normalizeRecordInput(array $data, array $config): array
    {
        $type = strtoupper(trim((string)($data['record_type'] ?? '')));
        if (!preg_match('/^[A-Z][A-Z0-9]{0,9}$/D', $type)) {
            throw new \InvalidArgumentException('Unsupported record type.');
        }

        $name = strtolower(trim((string)($data['record_name'] ?? '')));
        $domain = strtolower(rtrim((string)$config['domain_name'], '.'));
        if ($name === '' || $name === '@' || rtrim($name, '.') === $domain) {
            $name = '@';
        } else {
            if (str_ends_with($name, '.' . $domain . '.')) {
                $name = substr($name, 0, -strlen($domain) - 2);
            } elseif (str_ends_with($name, '.' . $domain)) {
                $name = substr($name, 0, -strlen($domain) - 1);
            }
            $name = rtrim($name, '.');
            if (!preg_match('/^(?:\*|[a-z0-9_-]+)(?:\.[a-z0-9_-]+)*$/D', $name)) {
                throw new \InvalidArgumentException('Use a relative DNS name such as www, _sip._tcp, or @.');
            }
        }

        $value = trim((string)($data['record_value'] ?? ''));
        if ($value === '' && $type !== 'TXT') {
            throw new \InvalidArgumentException('Record value is required.');
        }
        if (preg_match('/[\x00-\x1F]/', $value)) {
            throw new \InvalidArgumentException('Record value contains invalid control characters.');
        }

        $ttl = filter_var(
            $data['record_ttl'] ?? 3600,
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 1, 'max_range' => 2147483647]]
        );
        if ($ttl === false) {
            throw new \InvalidArgumentException('TTL must be a positive integer.');
        }

        $priority = filter_var(
            ($data['record_priority'] ?? '') === '' ? 0 : $data['record_priority'],
            FILTER_VALIDATE_INT,
            ['options' => ['min_range' => 0, 'max_range' => 65535]]
        );
        if ($priority === false) {
            throw new \InvalidArgumentException('Record priority must be between 0 and 65535.');
        }

        if ($type === 'A' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            throw new \InvalidArgumentException('Invalid IPv4 address for A record.');
        }
        if ($type === 'AAAA' && !filter_var($value, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            throw new \InvalidArgumentException('Invalid IPv6 address for AAAA record.');
        }

        $record = [
            'record_name' => $name,
            'record_type' => $type,
            'record_value' => $value,
            'record_ttl' => (int)$ttl,
            'record_priority' => in_array($type, ['MX', 'SRV'], true) ? (int)$priority : 0,
        ];

        if ($type === 'SRV') {
            if (preg_match('/^(\d+)\s+(\d+)\s+(\d+)\s+(.+)$/', $value, $m)) {
                $record['record_priority'] = (int)$m[1];
                $record['record_weight'] = (int)$m[2];
                $record['record_port'] = (int)$m[3];
                $record['record_value'] = trim($m[4]);
            } elseif (preg_match('/^(\d+)\s+(\d+)\s+(.+)$/', $value, $m)) {
                $record['record_weight'] = (int)$m[1];
                $record['record_port'] = (int)$m[2];
                $record['record_value'] = trim($m[3]);
            } else {
                throw new \InvalidArgumentException(
                    'SRV value must be "weight port target" or "priority weight port target".'
                );
            }
        }

        if (in_array($type, ['TXT', 'SPF'], true)
            && in_array($config['provider'], ['Desec', 'PowerDNS'], true)
            && !(str_starts_with($record['record_value'], '"') && str_ends_with($record['record_value'], '"'))) {
            $record['record_value'] = '"' . addcslashes($record['record_value'], "\\\"") . '"';
        }

        if ($config['provider'] === 'PowerDNS' && $type === 'CNAME') {
            $record['record_value'] = rtrim($record['record_value'], '.') . '.';
        }

        return $record;
    }

    private function dnssecState(CardoService $service, array $config): array
    {
        $capabilities = $service->getDNSSECCapabilities($config);
        if (!($capabilities['supported'] ?? false)) {
            return array_merge($capabilities, ['enabled' => false, 'ds' => []]);
        }

        $status = $service->getDNSSECStatus($config);
        $ds = $status['ds'] ?? null;
        if (($status['enabled'] ?? ($capabilities['enforced'] ?? false)) && ($ds === null || $ds === [])) {
            $ds = $service->getDSRecords($config);
        }
        if ($ds === null || $ds === '') {
            $ds = [];
        } elseif (!is_array($ds)) {
            $ds = [$ds];
        }

        return array_merge($capabilities, $status, [
            'enabled' => (bool)($status['enabled'] ?? ($capabilities['enforced'] ?? false)),
            'ds' => $ds,
        ]);
    }

    private function displayDsRecords(array $records): array
    {
        $result = [];
        foreach ($records as $record) {
            if (is_string($record)) {
                $parts = preg_split('/\s+/', trim($record), 4);
                if (count($parts) === 4) {
                    $result[] = [
                        'keytag' => $parts[0],
                        'algorithm' => $parts[1],
                        'digest_type' => $parts[2],
                        'digest' => $parts[3],
                        'full' => trim($record),
                    ];
                }
                continue;
            }
            if (is_array($record)) {
                $keyTag = $record['key_tag'] ?? $record['keytag'] ?? $record['keyTag'] ?? null;
                $algorithm = $record['algorithm'] ?? null;
                $digestType = $record['digest_type'] ?? $record['digestType'] ?? null;
                $digest = $record['digest'] ?? null;
                if ($keyTag !== null && $algorithm !== null && $digestType !== null && $digest !== null) {
                    $result[] = [
                        'keytag' => $keyTag,
                        'algorithm' => $algorithm,
                        'digest_type' => $digestType,
                        'digest' => $digest,
                        'full' => "{$keyTag} {$algorithm} {$digestType} {$digest}",
                    ];
                }
            }
        }
        return $result;
    }

    private function nameserversForZone(array $domain, array $config): array
    {
        $nameservers = getConfiguredNameservers();

        if (($config['provider'] ?? '') === 'Cloudflare') {
            try {
                $details = (new \Namingo\Cardo\DNS\Providers\Cloudflare($config))
                    ->getDomain((string)$domain['domain_name']);
                $assigned = array_values(array_filter($details['name_servers'] ?? [], 'is_string'));
                if ($assigned !== []) {
                    $nameservers = array_map(fn($ns) => rtrim($ns, '.'), $assigned);
                }
            } catch (\Throwable) {
                // Keep configured nameservers as a safe fallback.
            }
        }

        if ($nameservers === []) {
            $db = $this->container->get('db');
            $rows = $db->select(
                "SELECT value FROM records
                 WHERE domain_id = ? AND type = 'NS' AND host IN ('', '@')
                 ORDER BY value",
                [$domain['id']]
            ) ?: [];
            foreach ($rows as $row) {
                if (!empty($row['value'])) {
                    $nameservers[] = rtrim((string)$row['value'], '.');
                }
            }
        }

        return array_values(array_unique($nameservers));
    }

    public function listZones(Request $request, Response $response)
    {
        return view($response,'admin/zones/listZones.twig');
    }
   
    public function checkZone(Request $request, Response $response)
    {
        if ($request->getMethod() === 'POST') {
            // Retrieve POST data
            $data = $request->getParsedBody();
            $domainName = $data['domain_name'] ?? null;
            $token = $data['token'] ?? null;
            $claims = $data['claims'] ?? null;

            if ($domainName) {
                // Convert to Punycode if the domain is not in ASCII
                if (!mb_detect_encoding($domainName, 'ASCII', true)) {
                    $convertedDomain = idn_to_ascii($domainName, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
                    if ($convertedDomain === false) {
                        $this->container->get('flash')->addMessage('error', 'Zone conversion to Punycode failed');
                        return $response->withHeader('Location', '/zone/check')->withStatus(302);
                    } else {
                        $domainName = $convertedDomain;
                    }
                }

                $invalid_domain = validate_label($domainName, $this->container->get('db'));
                if ($invalid_domain) {
                    $this->container->get('flash')->addMessage('error', 'Domain ' . $domainName . ' is not available: ' . $invalid_domain);
                    return $response->withHeader('Location', '/zone/check')->withStatus(302);
                }

                $resolver = new DNSResolver([
                    'nameservers' => [ envi('DNS_RESOLVER') ?: '1.1.1.1' ],
                ]);
                $nsResponse  = null;
                $soaResponse = null;

                try {
                    $nsResponse = $resolver->query($domainName, 'NS');
                } catch (\NetDns2\Exception $e) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "NS lookup failed: " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                }
                
                if ($nsResponse === null || empty($nsResponse->answer)) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "No NS records found. Zone might not be properly delegated.",
                        'soa_serial' => null
                    ];

                    $this->container->get('flash')->addMessage('error', $nsCheck['error']);
                    return $response->withHeader('Location', '/zone/check')->withStatus(302);
                }

                if (empty($nsResponse->answer)) {
                    $nsCheck = [
                        'healthy'    => false,
                        'error'      => "No NS records found. Zone might not be properly delegated.",
                        'soa_serial' => null
                    ];
                }

                try {
                    $soaResponse = $resolver->query($domainName, 'SOA');
                } catch (\NetDns2\Exception\DnsException $e) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "SOA lookup failed (DNS error): " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                    $soaResponse = null;
                } catch (\NetDns2\Exception\RuntimeException $e) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "SOA lookup failed (resolver error): " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                    $soaResponse = null;
                } catch (\Throwable $e) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "SOA lookup failed: " . $e->getMessage(),
                        'soa_serial' => null
                    ];
                    $soaResponse = null;
                }

                if ($soaResponse === null) {
                    $this->container->get('flash')->addMessage('error', $soaCheck['error']);
                    return $response->withHeader('Location', '/zone/check')->withStatus(302);
                }

                if (empty($soaResponse->answer)) {
                    $soaCheck = [
                        'healthy'    => false,
                        'error'      => "No SOA record found for zone.",
                        'soa_serial' => null
                    ];
                }

                // Assume the first SOA record is the primary one.
                $soaRecord  = $soaResponse->answer[0];
                $soaSerial  = $soaRecord->serial;

                // 3. (Optional) Verify that all NS servers return the same SOA serial.
                $issues = [];
                foreach ($nsResponse->answer as $nsRecord) {
                    // Clean the NS server name (remove trailing dot).
                    $nsServer = rtrim($nsRecord->nsdname, '.');

                    try {
                        $resolver = new DNSResolver();
                        $nsRecord = (object) ['nsdname' => $nsServer]; 

                        // Clean the NS name
                        $nsServer = rtrim($nsRecord->nsdname, '.');

                        // Resolve NS hostname to an IP address
                        $resolverTemp = new DNSResolver();
                        $nsIpResponse = $resolverTemp->query($nsServer, 'A'); // Get IPv4 address (use 'AAAA' for IPv6)

                        if (!empty($nsIpResponse->answer)) {
                            $nsIp = strval($nsIpResponse->answer[0]->address);
                        } else {
                            throw new Exception("Could not resolve nameserver IP.");
                        }

                        // Set resolver to query this specific nameserver.
                        $resolver->nameservers = [$nsIp];
                        $nsSoaResponse = $resolver->query($domainName, 'SOA');

                        if (empty($nsSoaResponse->answer)) {
                            $issues[] = "Nameserver {$nsServer} did not return an SOA record.";
                            continue;
                        }

                        $nsSoaSerial = $nsSoaResponse->answer[0]->serial;
                        if ($nsSoaSerial != $soaSerial) {
                            $issues[] = "Nameserver {$nsServer} returned differing SOA serial ({$nsSoaSerial} vs expected {$soaSerial}).";
                        }
                    } catch (Exception $e) {
                        $issues[] = "Error querying nameserver {$nsServer}: " . $e->getMessage();
                    }
                }

                $healthy = empty($issues);

                $result = [
                    'healthy'    => $healthy,
                    'error'      => $healthy ? null : implode(" ", $issues),
                    'soa_serial' => $soaSerial
                ];

                if ($healthy) {
                    $this->container->get('flash')->addMessage('success', "Zone is healthy. SOA Serial: $soaSerial");
                } else {
                    $this->container->get('flash')->addMessage('warning', "Zone issues found: " . implode(", ", $issues));
                }
                return $response->withHeader('Location', '/zone/check')->withStatus(302);
            }
        }

        // Default view for GET requests or if POST data is not set
        return view($response,'admin/zones/checkZone.twig');
    }
    
    public function createZone(Request $request, Response $response)
    {
        if ((int)($_SESSION['auth_roles'] ?? -1) !== 0) {
            return $response->withHeader('Location', '/dashboard')->withStatus(302);
        }

        if ($request->getMethod() === 'POST') {
            $data = $request->getParsedBody();
            $db = $this->container->get('db');
            $pdo = $this->container->get('pdo');

            $domainName = strtolower(rtrim(trim((string)($data['domainName'] ?? '')), '.'));
            if ($domainName !== '' && !mb_detect_encoding($domainName, 'ASCII', true)) {
                $domainName = idn_to_ascii($domainName, IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46) ?: '';
            }

            if ($domainName === '' || validate_label($domainName, $db)) {
                $this->container->get('flash')->addMessage('error', 'Error creating zone: Invalid zone name');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            if ($db->selectValue('SELECT id FROM zones WHERE domain_name = ? LIMIT 1', [$domainName])) {
                $this->container->get('flash')->addMessage('error', 'Error creating zone: Zone name already exists');
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }

            try {
                $provider = (string)($data['provider'] ?? '');
                if ($provider === '') {
                    throw new \RuntimeException('DNS provider is required.');
                }

                $config = buildDnsProviderConfig($provider, $domainName);
                $service = new CardoService($pdo);
                $service->createDomain([
                    'client_id' => (int)$_SESSION['auth_user_id'],
                    'config' => json_encode($config, JSON_THROW_ON_ERROR),
                ]);

                // Cardo deliberately stores only its provider identity. Keep the
                // zone's structural provider settings too, never credentials.
                $db->update(
                    'zones',
                    ['config' => json_encode(dnsStructuralConfig($config), JSON_THROW_ON_ERROR)],
                    ['domain_name' => $domainName]
                );

                $created = $db->selectValue(
                    'SELECT created_at FROM zones WHERE domain_name = ? LIMIT 1',
                    [$domainName]
                );
                $this->container->get('flash')->addMessage(
                    'success',
                    'Zone ' . $domainName . ' has been created successfully on ' . $created
                );
                return $response->withHeader('Location', '/zone/update/' . $domainName)->withStatus(302);
            } catch (\Throwable $e) {
                $this->container->get('flash')->addMessage('error', 'Zone creation failed: ' . $e->getMessage());
                return $response->withHeader('Location', '/zone/create')->withStatus(302);
            }
        }

        return view($response, 'admin/zones/createZone.twig', [
            'providers' => getActiveProviders(),
        ]);
    }

    public function viewZone(Request $request, Response $response, $args)
    {
        $db = $this->container->get('db');
        $zone = strtolower(rtrim(trim((string)$args), '.'));

        if ($zone === '' || !preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $zone)) {
            $this->container->get('flash')->addMessage('error', 'Invalid zone format');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $this->ownedZone($zone);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $records = $db->select(
            "SELECT id, recordId, type, host, value, ttl, priority
             FROM records WHERE domain_id = ?
             ORDER BY CASE type
                WHEN 'SOA' THEN 1 WHEN 'NS' THEN 2 WHEN 'A' THEN 3
                WHEN 'AAAA' THEN 4 WHEN 'CNAME' THEN 5 WHEN 'MX' THEN 6
                WHEN 'TXT' THEN 7 WHEN 'SPF' THEN 8 WHEN 'SRV' THEN 9
                WHEN 'CAA' THEN 10 ELSE 99 END, host, value",
            [$domain['id']]
        ) ?: [];

        $users = $db->selectRow('SELECT id, email, username FROM users WHERE id = ?', [$domain['client_id']]);
        $domain['domain_name_o'] = $domain['domain_name'];
        if (str_contains($domain['domain_name'], 'xn--')) {
            $unicode = idn_to_utf8($domain['domain_name'], IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
            if ($unicode !== false) {
                $domain['domain_name'] = $unicode;
            }
        }

        return view($response, 'admin/zones/viewZone.twig', [
            'domain' => $domain,
            'records' => $records,
            'users' => $users,
            'currentUri' => $request->getUri()->getPath(),
        ]);
    }

    public function zoneDetails(Request $request, Response $response, $args) 
    {
        $db = $this->container->get('db');
        $uri = $request->getUri()->getPath();

        if (!$args) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $zone = strtolower(trim($args));

        if (!preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $zone)) {
            $this->container->get('flash')->addMessage('error', 'Invalid zone format');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $zone_owner = $db->selectValue('SELECT client_id FROM zones WHERE domain_name = ?', [$zone]);
        if ($zone_owner != $_SESSION['auth_user_id'] && $_SESSION["auth_roles"] != 0) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $db->selectRow('SELECT id, domain_name, client_id, created_at, updated_at, provider_id, zoneId, config FROM zones WHERE domain_name = ?',
        [ $zone ]);
        
        if (!$domain) {
            $this->container->get('flash')->addMessage('error', 'Zone not found');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }
        
        $resolverAddress = envi('DNS_RESOLVER') ?? '1.1.1.1';
        $config = json_decode($domain['config'], true);
        $provider = $config['provider'] ?? null;

        $client = new Client($resolverAddress);

        $types = [
            Record::TYPE_A,
            Record::TYPE_AAAA,
            Record::TYPE_CNAME,
            Record::TYPE_MX,
            Record::TYPE_TXT,
            Record::TYPE_NS,
            Record::TYPE_SOA,
            Record::TYPE_SRV,
            Record::TYPE_CAA,
        ];

        $recordsByType = [];
        $lookupErrors  = [];
        
        $typeNames = [
            Record::TYPE_A     => 'A',
            Record::TYPE_AAAA  => 'AAAA',
            Record::TYPE_CNAME => 'CNAME',
            Record::TYPE_MX    => 'MX',
            Record::TYPE_TXT   => 'TXT',
            Record::TYPE_NS    => 'NS',
            Record::TYPE_SOA   => 'SOA',
            Record::TYPE_SRV   => 'SRV',
            Record::TYPE_CAA   => 'CAA',
        ];

        foreach ($types as $type) {
            try {
                $query = Message::query(
                    new Question($domain['domain_name'], $type)
                );

                $dnsResponse = $client->query($query);

                foreach ($dnsResponse->answers as $answer) {
                    $typeName = $typeNames[$answer->type] ?? (string) $answer->type;

                    $recordsByType[$typeName][] = [
                        'name'  => rtrim($answer->name, '.'),
                        'ttl'   => $answer->ttl,
                        'type'  => $typeName,
                        'value' => (string) $answer->rdata,
                    ];
                }
            } catch (\Throwable $e) {
                $typeName = $typeNames[$type] ?? (string) $type;
                $lookupErrors[] = sprintf('%s lookup failed: %s', $typeName, $e->getMessage());
            }
        }

        if (!empty($lookupErrors)) {
            $this->container->get('flash')->addMessage(
                'error',
                'Unable to load DNS records for this zone (resolver error). Please try again later.'
            );
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        return view($response, 'admin/zones/zoneDetails.twig', [
            'domain'         => $domain,
            'recordsByType'  => $recordsByType,
            'resolver'       => $resolverAddress,
            'currentUri'     => $uri,
            'provider'       => $provider,
        ]);
    }

    public function zoneDNSSEC(Request $request, Response $response, $args)
    {
        $zone = strtolower(rtrim(trim((string)$args), '.'));
        $domain = $this->ownedZone($zone);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        if ($request->getMethod() !== 'POST') {
            return $response->withHeader('Location', '/zone/update/' . $zone)->withStatus(303);
        }

        try {
            $config = $this->cardoConfig($domain);
            $service = new CardoService($this->container->get('pdo'));
            $capabilities = $service->getDNSSECCapabilities($config);
            $action = strtolower((string)(($request->getParsedBody())['action'] ?? ''));

            if (!($capabilities['supported'] ?? false)) {
                throw new \RuntimeException('DNSSEC is not supported by this provider.');
            }

            if ($action === 'enable') {
                if (!($capabilities['can_enable'] ?? false)) {
                    throw new \RuntimeException('DNSSEC cannot be enabled for this provider.');
                }
                $service->enableDNSSEC($config);
                $message = 'DNSSEC enabled successfully.';
            } elseif ($action === 'disable') {
                if (!($capabilities['can_disable'] ?? false)) {
                    throw new \RuntimeException('DNSSEC cannot be disabled for this provider.');
                }
                $service->disableDNSSEC($config);
                $message = 'DNSSEC disabled successfully.';
            } else {
                throw new \InvalidArgumentException('Invalid DNSSEC action.');
            }

            $this->container->get('flash')->addMessage('success', $message);
        } catch (\Throwable $e) {
            $this->container->get('flash')->addMessage('error', 'DNSSEC update failed: ' . $e->getMessage());
        }

        return $response->withHeader('Location', '/zone/update/' . $zone)->withStatus(303);
    }

    public function updateZone(Request $request, Response $response, $args)
    {
        $db = $this->container->get('db');
        $pdo = $this->container->get('pdo');
        $zone = strtolower(rtrim(trim((string)$args), '.'));

        if ($zone === '' || !preg_match('/^([a-z0-9]([-a-z0-9]*[a-z0-9])?\.)*[a-z0-9]([-a-z0-9]*[a-z0-9])?$/', $zone)) {
            $this->container->get('flash')->addMessage('error', 'Invalid zone format');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $this->ownedZone($zone);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        try {
            $config = $this->cardoConfig($domain);
            $service = new CardoService($pdo);
            $dnssec = $this->dnssecState($service, $config);
            $nameservers = $this->nameserversForZone($domain, $config);
            $canDeleteZone = ($config['provider'] ?? '') !== 'GandiLiveDNS';
            if (($config['provider'] ?? '') === 'Scaleway') {
                $parent = strtolower(rtrim((string)($config['parent_domain'] ?? ''), '.'));
                $zoneName = strtolower(rtrim((string)$domain['domain_name'], '.'));
                $canDeleteZone = $parent !== ''
                    && $zoneName !== $parent
                    && str_ends_with($zoneName, '.' . $parent);
            }
        } catch (\Throwable $e) {
            $dnssec = ['supported' => false, 'enabled' => false, 'can_enable' => false, 'can_disable' => false, 'ds' => []];
            $nameservers = getConfiguredNameservers();
            $canDeleteZone = false;
            $this->container->get('flash')->addMessage('error', 'Could not load provider status: ' . $e->getMessage());
        }

        $records = $db->select(
            "SELECT id, recordId, type, host, value, ttl, priority
             FROM records WHERE domain_id = ?
             ORDER BY CASE type
                WHEN 'SOA' THEN 1 WHEN 'NS' THEN 2 WHEN 'A' THEN 3
                WHEN 'AAAA' THEN 4 WHEN 'CNAME' THEN 5 WHEN 'MX' THEN 6
                WHEN 'TXT' THEN 7 WHEN 'SPF' THEN 8 WHEN 'SRV' THEN 9
                WHEN 'CAA' THEN 10 ELSE 99 END, host, value",
            [$domain['id']]
        ) ?: [];

        $users = $db->selectRow('SELECT id, email, username FROM users WHERE id = ?', [$domain['client_id']]);
        $domain['domain_name_o'] = $domain['domain_name'];
        if (str_contains($domain['domain_name'], 'xn--')) {
            $unicode = idn_to_utf8($domain['domain_name'], IDNA_NONTRANSITIONAL_TO_ASCII, INTL_IDNA_VARIANT_UTS46);
            if ($unicode !== false) {
                $domain['domain_name'] = $unicode;
            }
        }

        $_SESSION['domains_to_update'] = [$domain['domain_name_o']];

        return view($response, 'admin/zones/updateZone.twig', [
            'domain' => $domain,
            'records' => $records,
            'users' => $users,
            'registrar' => (int)($_SESSION['auth_roles'] ?? 0) !== 0,
            'currentUri' => $request->getUri()->getPath(),
            'dnssec' => $dnssec,
            'dsList' => $this->displayDsRecords($dnssec['ds'] ?? []),
            'nameservers' => $nameservers,
            'canDeleteZone' => $canDeleteZone,
        ]);
    }

    public function updateZoneProcess(Request $request, Response $response)
    {
        if ($request->getMethod() !== 'POST') {
            return $response->withHeader('Location', '/zones')->withStatus(303);
        }

        $domainName = (string)($_SESSION['domains_to_update'][0] ?? '');
        if ($domainName === '') {
            $this->container->get('flash')->addMessage('error', 'No zone specified for update.');
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $domain = $this->ownedZone($domainName);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        try {
            $config = $this->cardoConfig($domain);
            $record = $this->normalizeRecordInput((array)$request->getParsedBody(), $config);
            (new CardoService($this->container->get('pdo')))->addRecord($record + $config);
            $this->container->get('flash')->addMessage('success', 'DNS record added successfully.');
        } catch (\Throwable $e) {
            $this->container->get('flash')->addMessage('error', 'DNS record creation failed: ' . $e->getMessage());
        }

        return $response->withHeader('Location', '/zone/update/' . $domainName)->withStatus(303);
    }

    public function zoneUpdateRecord(Request $request, Response $response)
    {
        if ($request->getMethod() !== 'POST') {
            return $response->withHeader('Location', '/zones')->withStatus(303);
        }

        $data = (array)$request->getParsedBody();
        $domainName = (string)($_SESSION['domains_to_update'][0] ?? '');
        $domain = $this->ownedZone($domainName);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        $localId = filter_var($data['record_id'] ?? null, FILTER_VALIDATE_INT);
        if (!$localId) {
            $this->container->get('flash')->addMessage('error', 'Record ID is invalid.');
            return $response->withHeader('Location', '/zone/update/' . $domainName)->withStatus(302);
        }

        $db = $this->container->get('db');
        $stored = $db->selectRow(
            'SELECT id, recordId, type, host, value, ttl, priority
             FROM records WHERE id = ? AND domain_id = ? LIMIT 1',
            [$localId, $domain['id']]
        );
        if (!$stored) {
            $this->container->get('flash')->addMessage('error', 'Record not found.');
            return $response->withHeader('Location', '/zone/update/' . $domainName)->withStatus(302);
        }

        try {
            $config = $this->cardoConfig($domain);
            $service = new CardoService($this->container->get('pdo'));
            $action = strtolower((string)($data['action'] ?? 'update'));

            if ($action === 'delete') {
                $service->delRecord([
                    'domain_name' => $domainName,
                    'record_id' => (int)$stored['id'],
                    'record_name' => (string)$stored['host'],
                    'record_type' => (string)$stored['type'],
                    'record_value' => (string)$stored['value'],
                    'record_priority' => (int)($stored['priority'] ?? 0),
                ] + $config);
                $this->container->get('flash')->addMessage('success', 'DNS record deleted successfully.');
            } else {
                // Record identity comes from the selected local row, never from
                // client-supplied old-value/type/name fields.
                $data['record_name'] = (string)$stored['host'];
                $data['record_type'] = (string)$stored['type'];
                if (!array_key_exists('record_priority', $data) || $data['record_priority'] === '') {
                    $data['record_priority'] = (int)($stored['priority'] ?? 0);
                }
                $record = $this->normalizeRecordInput($data, $config);
                $record['record_id'] = (int)$stored['id'];
                $record['old_value'] = (string)$stored['value'];

                $service->updateRecord($record + $config);
                $this->container->get('flash')->addMessage('success', 'DNS record updated successfully.');
            }
        } catch (\Throwable $e) {
            $this->container->get('flash')->addMessage('error', 'DNS record update failed: ' . $e->getMessage());
        }

        return $response->withHeader('Location', '/zone/update/' . $domainName)->withStatus(303);
    }

    public function deleteZone(Request $request, Response $response, $args)
    {
        $zone = strtolower(rtrim(trim((string)$args), '.'));
        $domain = $this->ownedZone($zone);
        if (!$domain) {
            return $response->withHeader('Location', '/zones')->withStatus(302);
        }

        if ($request->getMethod() !== 'POST') {
            return $response->withHeader('Location', '/zone/update/' . $zone)->withStatus(303);
        }

        try {
            $config = $this->cardoConfig($domain);
            (new CardoService($this->container->get('pdo')))->deleteDomain([
                'config' => json_encode($config, JSON_THROW_ON_ERROR),
            ]);
            $this->container->get('flash')->addMessage('success', 'Zone ' . $zone . ' deleted successfully.');
            return $response->withHeader('Location', '/zones')->withStatus(303);
        } catch (\Throwable $e) {
            // Cardo leaves the local zone intact if remote deletion fails. This
            // is important for Gandi and Scaleway managed root zones.
            $this->container->get('flash')->addMessage('error', 'Zone deletion failed: ' . $e->getMessage());
            return $response->withHeader('Location', '/zone/update/' . $zone)->withStatus(303);
        }
    }

}