<?php
// Run on isolated LAB-FW as root. Keep the VM MAC outside Git.
if ($argc !== 3 || $argv[1] !== '--apply'
    || !preg_match('/^(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$/D', $argv[2])) {
    fwrite(STDERR, "Usage: php Reserve-Workstation.php --apply <WORKSTATION_MAC>\n");
    exit(2);
}

$mac = strtolower($argv[2]);
$address = '10.77.10.139';
$path = '/conf/config.xml';
$doc = new DOMDocument();
$doc->preserveWhiteSpace = false;
$doc->formatOutput = true;
if (!$doc->load($path)) {
    throw new RuntimeException('Cannot load OPNsense configuration');
}
$xpath = new DOMXPath($doc);
$dnsmasq = $xpath->query('/opnsense/dnsmasq')->item(0);
if (!$dnsmasq || $xpath->evaluate('string(enable)', $dnsmasq) !== '1') {
    throw new RuntimeException('Enabled Dnsmasq model is required');
}
foreach ($xpath->query('hosts', $dnsmasq) as $host) {
    $existingIp = $xpath->evaluate('string(ip)', $host);
    $existingMac = strtolower($xpath->evaluate('string(hwaddr)', $host));
    if ($existingIp === $address || $existingMac === $mac) {
        if ($existingIp === $address && $existingMac === $mac) {
            echo "Workstation reservation already exists; no change.\n";
            exit(0);
        }
        throw new RuntimeException('Conflicting host reservation');
    }
}

$host = $doc->createElement('hosts');
$bytes = random_bytes(16);
$bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
$bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
$hex = bin2hex($bytes);
$host->setAttribute('uuid', implode('-', [substr($hex, 0, 8), substr($hex, 8, 4),
    substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]));
foreach (['host' => 'ws01', 'domain' => 'corp.example.test', 'ip' => $address,
          'hwaddr' => $mac, 'descr' => 'LAB-WS01 fixed lab lease'] as $name => $value) {
    $host->appendChild($doc->createElement($name, $value));
}
$dnsmasq->appendChild($host);

$backup = $path . '.lab-dhcp-' . date('Ymd-His');
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
echo "Saved LAB-WS01 reservation for $address. Reload Dnsmasq and renew the lease.\n";
echo 'Private rollback backup: ' . $backup . PHP_EOL;
