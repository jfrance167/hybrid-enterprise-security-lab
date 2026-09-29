<?php
// Temporary installation-only egress. Run on isolated LAB-FW as root.
// Keeps the original configuration as a dated backup.
if (($argv[1] ?? '') !== '--enable-temporary-egress' || count($argv) !== 2) {
    fwrite(STDERR, "This adds broad outbound rules for installation only.\n"
        . "Run with --enable-temporary-egress to acknowledge that scope.\n"
        . "Remove or narrow the rules before claiming firewall hardening.\n");
    exit(2);
}
$path = '/conf/config.xml';
$doc = new DOMDocument();
$doc->preserveWhiteSpace = false;
$doc->formatOutput = true;
if (!$doc->load($path)) {
    fwrite(STDERR, "Unable to read OPNsense configuration\n");
    exit(1);
}
$xpath = new DOMXPath($doc);
$rules = $xpath->query('/opnsense/OPNsense/Firewall/Filter/rules')->item(0);
if (!$rules) {
    fwrite(STDERR, "Firewall rules model missing\n");
    exit(1);
}
// Never restore temporary broad egress after the scoped allowlist is installed.
foreach ($xpath->query('rule', $rules) as $rule) {
    if (str_starts_with($xpath->evaluate('string(description)', $rule), 'LAB-ALLOW ')) {
        fwrite(STDERR, "Scoped LAB-ALLOW rules already exist; temporary egress is refused.\n");
        exit(2);
    }
}
$template = null;
foreach ($xpath->query('rule', $rules) as $rule) {
    if ($xpath->evaluate('string(interface)', $rule) === 'lan'
        && $xpath->evaluate('string(ipprotocol)', $rule) === 'inet'
        && $xpath->evaluate('string(action)', $rule) === 'pass') {
        $template = $rule;
        break;
    }
}
if (!$template) {
    fwrite(STDERR, "IPv4 LAN template rule missing\n");
    exit(1);
}
foreach (['opt1' => 'Lab server subnet outbound', 'opt2' => 'Lab management subnet outbound'] as $interface => $description) {
    if ($xpath->query('rule[description="' . $description . '"]', $rules)->length) {
        continue;
    }
    $rule = $template->cloneNode(true);
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    $rule->setAttribute('uuid', implode('-', [substr($hex, 0, 8), substr($hex, 8, 4),
        substr($hex, 12, 4), substr($hex, 16, 4), substr($hex, 20, 12)]));
    foreach (['interface' => $interface, 'source_net' => $interface,
              'description' => $description, 'log' => '1'] as $field => $value) {
        $xpath->query($field, $rule)->item(0)->nodeValue = $value;
    }
    $rules->appendChild($rule);
}
$backup = $path . '.lab-' . date('Ymd-His');
if (!copy($path, $backup) || $doc->save($path) === false) {
    fwrite(STDERR, "Unable to save firewall configuration\n");
    exit(1);
}
echo "Saved rules; backup: $backup\n";
echo "Temporary broad egress is active; narrow or remove before acceptance.\n";
