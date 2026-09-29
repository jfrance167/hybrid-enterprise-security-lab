<?php
// Requires the official OPNsense os-wazuh-agent plugin on isolated LAB-FW.
// Uses the agent's authenticated channel and collects only firewall filterlog.
if ($argc !== 2 || $argv[1] !== '--apply') {
    fwrite(STDERR, "Usage: php Configure-FirewallWazuhAgent.php --apply\n");
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
$opnsense = $xpath->query('/opnsense/OPNsense')->item(0);
if (!$opnsense) {
    throw new RuntimeException('OPNsense configuration model is missing');
}
$agent = $xpath->query('WazuhAgent', $opnsense)->item(0);
if (!$agent) {
    $agent = $doc->createElement('WazuhAgent');
    $opnsense->appendChild($agent);
}

function setAgentField(DOMDocument $doc, DOMXPath $xpath, DOMElement $parent,
    string $section, string $name, string $value): void
{
    $container = $xpath->query($section, $parent)->item(0);
    if (!$container) {
        $container = $doc->createElement($section);
        $parent->appendChild($container);
    }
    $field = $xpath->query($name, $container)->item(0);
    if (!$field) {
        $field = $doc->createElement($name);
        $container->appendChild($field);
    }
    $field->nodeValue = $value;
}

foreach ([
    ['general', 'enabled', '1'],
    ['general', 'server_address', '10.77.30.10'],
    ['general', 'agent_name', 'LAB-FW'],
    ['general', 'protocol', 'tcp'],
    ['general', 'port', '1514'],
    ['general', 'debug_level', '0'],
    ['auth', 'port', '1515'],
    ['logcollector', 'syslog_programs', 'filterlog'],
    ['logcollector', 'remote_commands', '0'],
    ['logcollector', 'suricata_eve_log', '0'],
    ['rootcheck', 'enabled', '0'],
    ['syscollector', 'enabled', '0'],
    ['syscheck', 'enabled', '0'],
    ['active_response', 'enabled', '0'],
    ['active_response', 'remote_commands', '0'],
] as [$section, $name, $value]) {
    setAgentField($doc, $xpath, $agent, $section, $name, $value);
}

$backup = $path . '.lab-wazuh-agent-' . date('Ymd-His');
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
echo "Saved filterlog-only Wazuh agent settings; private backup: $backup\n";
echo "Reconfigure and start the plugin, then verify agent registration and a new deny alert.\n";
