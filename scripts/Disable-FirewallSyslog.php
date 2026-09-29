<?php
// Remove the older cleartext UDP filterlog destination after confirming Wazuh agent ingestion.
if ($argc !== 2 || $argv[1] !== '--apply') {
    fwrite(STDERR, "Usage: php Disable-FirewallSyslog.php --apply\n");
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
$removed = 0;
foreach ($xpath->query('destination', $targets) as $target) {
    if ($xpath->evaluate('string(description)', $target) === 'LAB-FW to Wazuh isolated UDP') {
        $targets->removeChild($target);
        $removed++;
    }
}
if ($removed === 0) {
    echo "Legacy UDP destination already absent.\n";
    exit(0);
}
$backup = $path . '.lab-before-disable-syslog-' . date('Ymd-His');
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
echo "Removed {$removed} legacy UDP destination(s); private backup: {$backup}\n";
echo "Reload Syslog and verify the UDP target is absent.\n";
