<?php
// Run only at the isolated LAB-FW console after reviewing the rule matrix.
// A dated, private configuration backup is created before any change.
if ($argc !== 2 || $argv[1] !== '--apply') {
    fwrite(STDERR, "Usage: php Apply-FirewallAllowlist.php --apply\n");
    exit(2);
}

$path = '/conf/config.xml';
$doc = new DOMDocument();
$doc->preserveWhiteSpace = false;
$doc->formatOutput = true;
if (!$doc->load($path)) {
    throw new RuntimeException('Cannot load OPNsense configuration');
}
$xpath = new DOMXPath($doc);
$rules = $xpath->query('/opnsense/OPNsense/Firewall/Filter/rules')->item(0);
if (!$rules) {
    throw new RuntimeException('Firewall rules model is missing');
}

$broadDescriptions = [
    'Default allow LAN to any rule',
    'Default allow LAN IPv6 to any rule',
    'Lab server subnet outbound',
    'Lab management subnet outbound',
];
$broad = [];
foreach ($xpath->query('rule', $rules) as $rule) {
    $description = $xpath->evaluate('string(description)', $rule);
    if (in_array($description, $broadDescriptions, true)) {
        if (isset($broad[$description])) {
            throw new RuntimeException('Duplicate broad rule: ' . $description);
        }
        $broad[$description] = $rule;
    }
}
foreach ($broadDescriptions as $description) {
    if (!isset($broad[$description])) {
        throw new RuntimeException('Expected broad rule missing: ' . $description);
    }
}
$template = $broad['Default allow LAN to any rule'];

// Every tuple is interface, source, destination, protocol, port, description.
// Empty port means all ports, which is not permitted in this allowlist.
$matrix = [
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '53', 'LAB-ALLOW WS AD DNS TCP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'udp', '53', 'LAB-ALLOW WS AD DNS UDP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '88', 'LAB-ALLOW WS Kerberos TCP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'udp', '88', 'LAB-ALLOW WS Kerberos UDP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '389', 'LAB-ALLOW WS LDAP TCP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'udp', '389', 'LAB-ALLOW WS LDAP UDP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '464', 'LAB-ALLOW WS password change TCP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'udp', '464', 'LAB-ALLOW WS password change UDP'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'udp', '123', 'LAB-ALLOW WS time'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '135', 'LAB-ALLOW WS AD RPC mapper'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '445', 'LAB-ALLOW WS policy SMB'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '3268', 'LAB-ALLOW WS global catalog'],
    ['lan', '10.77.10.0/24', '10.77.20.10', 'tcp', '49152:65535', 'LAB-ALLOW WS AD dynamic RPC'],
    ['lan', '10.77.10.0/24', '10.77.20.20', 'tcp', '80', 'LAB-ALLOW WS service desk HTTP'],
    ['lan', '10.77.10.0/24', '10.77.30.10', 'tcp', '1514', 'LAB-ALLOW WS Wazuh telemetry'],
    ['opt1', '10.77.20.10', '10.77.30.10', 'tcp', '1514', 'LAB-ALLOW DC Wazuh telemetry'],
    ['opt1', '10.77.20.20', '10.77.30.10', 'tcp', '1514', 'LAB-ALLOW APP Wazuh telemetry'],
    ['opt1', '10.77.20.20', '10.77.20.1', 'udp', '53', 'LAB-ALLOW APP DNS UDP'],
    ['opt1', '10.77.20.20', '10.77.20.1', 'tcp', '53', 'LAB-ALLOW APP DNS TCP'],
    ['opt1', '10.77.20.10', '10.77.20.1', 'udp', '53', 'LAB-ALLOW DC forwarder DNS UDP'],
    ['opt1', '10.77.20.10', '10.77.20.1', 'tcp', '53', 'LAB-ALLOW DC forwarder DNS TCP'],
    ['opt1', '10.77.20.0/24', '!10.77.0.0/16', 'tcp', '443', 'LAB-ALLOW server public updates'],
    ['opt2', '10.77.30.10', '10.77.30.1', 'udp', '53', 'LAB-ALLOW SIEM DNS UDP'],
    ['opt2', '10.77.30.10', '10.77.30.1', 'tcp', '53', 'LAB-ALLOW SIEM DNS TCP'],
    ['opt2', '10.77.30.10', '!10.77.0.0/16', 'tcp', '443', 'LAB-ALLOW SIEM public updates'],
];

function setField(DOMDocument $doc, DOMXPath $xpath, DOMElement $rule, string $name, string $value): void
{
    $field = $xpath->query($name, $rule)->item(0);
    if (!$field) {
        $field = $doc->createElement($name);
        $rule->appendChild($field);
    }
    $field->nodeValue = $value;
}

// Re-running replaces only this script's rules, never unrelated policy.
foreach (iterator_to_array($xpath->query('rule', $rules)) as $rule) {
    if (str_starts_with($xpath->evaluate('string(description)', $rule), 'LAB-ALLOW ')) {
        $rules->removeChild($rule);
    }
}
foreach ($matrix as [$interface, $source, $destination, $protocol, $port, $description]) {
    $rule = $template->cloneNode(true);
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    $rule->setAttribute('uuid', implode('-', [substr($hex, 0, 8), substr($hex, 8, 4),
        substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]));
    $negated = str_starts_with($destination, '!');
    $destination = ltrim($destination, '!');
    foreach ([
        'enabled' => '1', 'interface' => $interface, 'source_net' => $source,
        'source_not' => '0', 'destination_net' => $destination,
        'destination_not' => $negated ? '1' : '0',
        'protocol' => $protocol, 'ipprotocol' => 'inet',
        'destination_port' => $port, 'action' => 'pass', 'quick' => '1',
        'direction' => 'in', 'log' => '1', 'description' => $description,
    ] as $field => $value) {
        setField($doc, $xpath, $rule, $field, $value);
    }
    $rules->insertBefore($rule, $template);
}
foreach ($broad as $rule) {
    setField($doc, $xpath, $rule, 'enabled', '0');
}

$backup = $path . '.lab-allowlist-' . date('Ymd-His');
if (!copy($path, $backup)) {
    throw new RuntimeException('Cannot create private configuration backup');
}
$tmp = $path . '.lab-new-' . bin2hex(random_bytes(4));
if ($doc->save($tmp) === false) {
    throw new RuntimeException('Cannot write new configuration');
}
chmod($tmp, fileperms($path) & 0777);
if (!rename($tmp, $path)) {
    throw new RuntimeException('Cannot replace configuration; backup: ' . $backup);
}
echo 'Saved ' . count($matrix) . ' allow rules and disabled four broad passes.' . PHP_EOL;
echo 'Private rollback backup: ' . $backup . PHP_EOL;
echo "Run configctl filter reload, inspect pfctl -sr, then test approved and denied flows.\n";
