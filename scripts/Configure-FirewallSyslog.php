<?php
// Lab-only UDP forwarding over the isolated management network.
// The transport is not encrypted; see FIREWALL_POLICY.md before reuse.
if ($argc !== 2 || $argv[1] !== '--apply') {
    fwrite(STDERR, "Usage: php Configure-FirewallSyslog.php --apply\n");
    exit(2);
}
$path = '/conf/config.xml';
$doc = new DOMDocument();
$doc->preserveWhiteSpace = false;
$doc->formatOutput = true;
if (!$doc->load($path)) {
    throw new RuntimeException('Cannot load firewall configuration');
}
$xpath = new DOMXPath($doc);
$targets = $xpath->query('/opnsense/OPNsense/Syslog/destinations')->item(0);
if (!$targets) {
    throw new RuntimeException('Syslog destination model is missing');
}
$target = null;
foreach ($xpath->query('destination', $targets) as $candidate) {
    if ($xpath->evaluate('string(description)', $candidate) === 'LAB-FW to Wazuh isolated UDP') {
        $target = $candidate;
        break;
    }
}
if ($target) {
    $program = $xpath->query('program', $target)->item(0);
    if (!$program) {
        throw new RuntimeException('Existing syslog target has no program field');
    }
    if ($program->nodeValue === 'filterlog') {
        echo "Lab filterlog target already exists; no change.\n";
        exit(0);
    }
    $program->nodeValue = 'filterlog';
} else {
    $target = $doc->createElement('destination');
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    $target->setAttribute('uuid', implode('-', [substr($hex, 0, 8), substr($hex, 8, 4),
        substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]));
    foreach ([
        'enabled' => '1', 'transport' => 'udp4', 'program' => 'filterlog',
        'level' => '', 'facility' => '', 'hostname' => '10.77.30.10',
        'certificate' => '', 'port' => '514', 'rfc5424' => '0',
        'description' => 'LAB-FW to Wazuh isolated UDP',
    ] as $name => $value) {
        $target->appendChild($doc->createElement($name, $value));
    }
    $targets->appendChild($target);
}
$backup = $path . '.lab-syslog-' . date('Ymd-His');
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
echo 'Saved filterlog-only UDP syslog target; private backup: ' . $backup . PHP_EOL;
echo "Reload Syslog and verify a matching deny at the Wazuh manager.\n";
