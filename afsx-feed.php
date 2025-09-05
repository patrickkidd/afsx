<?php
/**
 * Plugin Name: AFSX
 * Plugin URI: https://github.com/patrickkidd/afsx
 * Description: A WordPress plugin that provides an 'afsx' shortcode to display X (Twitter) feeds with caching and default X timeline styling.
 * Version: 1.0.0
 * Author: AFSX
 * License: GPL v2 or later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 */

if (!defined('ABSPATH')) {
    exit;
}

// Plugin Configuration Constants
define('AFSX_PLUGIN_VERSION', '1.0.0');
define('AFSX_DEFAULT_CACHE_DURATION', 900); // 15 minutes in seconds
define('AFSX_ERROR_CACHE_DURATION', 300); // 5 minutes for errors
define('AFSX_USER_ID_CACHE_DURATION', 86400); // 24 hours for user ID mapping
define('AFSX_DEFAULT_TWEET_COUNT', 5);
define('AFSX_MAX_TWEET_COUNT', 100);
define('AFSX_API_BASE_URL', 'https://api.twitter.com/2');
define('AFSX_TWITTER_BASE_URL', 'https://twitter.com');
define('AFSX_OAUTH_VERSION', '1.0');
define('AFSX_OAUTH_SIGNATURE_METHOD', 'HMAC-SHA1');

// Plugin Option Keys
define('AFSX_OPTION_API_KEY', 'afsx_api_key');
define('AFSX_OPTION_API_SECRET', 'afsx_api_secret');
define('AFSX_OPTION_ACCESS_TOKEN', 'afsx_access_token');
define('AFSX_OPTION_ACCESS_TOKEN_SECRET', 'afsx_access_token_secret');

// Plugin Settings
define('AFSX_SETTINGS_GROUP', 'afsx_settings');
define('AFSX_SETTINGS_SECTION', 'afsx_api_section');
define('AFSX_ADMIN_CAPABILITY', 'manage_options');
define('AFSX_ADMIN_MENU_SLUG', 'afsx-feed-settings');

// API Configuration
define('AFSX_TWEET_FIELDS', 'created_at,public_metrics,author_id');
define('AFSX_USER_FIELDS', 'name,username,profile_image_url');
define('AFSX_EXPANSIONS', 'author_id');

// Cache Configuration
define('AFSX_CACHE_PREFIX', 'afsx_feed_');
define('AFSX_USER_CACHE_PREFIX', 'afsx_user_');
define('AFSX_ERROR_CACHE_PREFIX', 'afsx_error_');

// Logging Configuration
define('AFSX_LOG_OPTION', 'afsx_api_logs');
define('AFSX_MAX_LOG_ENTRIES', 100);

class AFSX_Feed {
    
    public function __construct() {
        add_action('init', array($this, 'init'));
        add_action('wp_enqueue_scripts', array($this, 'enqueue_styles'));
        add_action('admin_menu', array($this, 'add_admin_menu'));
        add_action('admin_init', array($this, 'admin_init'));
    }
    
    public function init() {
        add_shortcode('afsx', array($this, 'afsx_shortcode'));
    }
    
    public function enqueue_styles() {
        wp_enqueue_style('afsx-feed-style', plugin_dir_url(__FILE__) . 'assets/style.css', array(), AFSX_PLUGIN_VERSION);
    }
    
    public function afsx_shortcode($atts) {
        $atts = shortcode_atts(array(
            'username' => '',
            'count' => AFSX_DEFAULT_TWEET_COUNT,
            'cache_time' => AFSX_DEFAULT_CACHE_DURATION
        ), $atts);
        
        if (empty($atts['username'])) {
            return '<div class="afsx-error">Error: Username is required for afsx shortcode.</div>';
        }
        
        $feed_data = $this->get_cached_feed($atts['username'], (int)$atts['count'], (int)$atts['cache_time']);
        
        if (is_wp_error($feed_data)) {
            return '<div class="afsx-error">Error loading feed: ' . $feed_data->get_error_message() . '</div>';
        }
        
        return $this->render_feed($feed_data);
    }
    
    private function get_cached_feed($username, $count, $cache_time) {
        $cache_key = AFSX_CACHE_PREFIX . $username . '_' . $count;
        $error_cache_key = AFSX_ERROR_CACHE_PREFIX . $username . '_' . $count;
        
        // Check for successful cached data first
        $cached_data = get_transient($cache_key);
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        // Check for cached errors to prevent rapid retries
        $cached_error = get_transient($error_cache_key);
        if ($cached_error !== false) {
            return $cached_error;
        }
        
        $feed_data = $this->fetch_x_feed($username, $count);
        
        if (is_wp_error($feed_data)) {
            // Cache errors for shorter duration to prevent retry storms
            $error_code = $feed_data->get_error_code();
            $cache_duration = ($error_code === 'api_error_429') ? AFSX_ERROR_CACHE_DURATION * 2 : AFSX_ERROR_CACHE_DURATION;
            set_transient($error_cache_key, $feed_data, $cache_duration);
        } else {
            // Cache successful data and clear any error cache
            set_transient($cache_key, $feed_data, $cache_time);
            delete_transient($error_cache_key);
        }
        
        return $feed_data;
    }
    
    private function fetch_x_feed($username, $count) {
        $api_key = get_option(AFSX_OPTION_API_KEY);
        $api_secret = get_option(AFSX_OPTION_API_SECRET);
        $access_token = get_option(AFSX_OPTION_ACCESS_TOKEN);
        $access_token_secret = get_option(AFSX_OPTION_ACCESS_TOKEN_SECRET);
        
        if (empty($api_key) || empty($api_secret) || empty($access_token) || empty($access_token_secret)) {
            return new WP_Error('missing_credentials', 'X API credentials are not configured. Please check the plugin settings.');
        }
        
        // Check for cached user ID first
        $user_cache_key = AFSX_USER_CACHE_PREFIX . $username;
        $user_id = get_transient($user_cache_key);
        
        if ($user_id === false) {
            // User ID not cached, fetch it
            $url = AFSX_API_BASE_URL . '/users/by/username/' . $username;
            $user_response = $this->make_api_request($url, array(), $api_key, $api_secret, $access_token, $access_token_secret);
            
            if (is_wp_error($user_response)) {
                return $user_response;
            }
            
            $user_data = json_decode($user_response, true);
            
            if (!isset($user_data['data']['id'])) {
                return new WP_Error('user_not_found', 'User not found: ' . $username);
            }
            
            $user_id = $user_data['data']['id'];
            
            // Cache user ID for 24 hours
            set_transient($user_cache_key, $user_id, AFSX_USER_ID_CACHE_DURATION);
        }
        
        // Get user tweets
        $tweets_url = AFSX_API_BASE_URL . '/users/' . $user_id . '/tweets';
        $tweets_params = array(
            'max_results' => min($count, AFSX_MAX_TWEET_COUNT),
            'tweet.fields' => AFSX_TWEET_FIELDS,
            'user.fields' => AFSX_USER_FIELDS,
            'expansions' => AFSX_EXPANSIONS
        );
        
        $tweets_response = $this->make_api_request($tweets_url, $tweets_params, $api_key, $api_secret, $access_token, $access_token_secret);
        
        if (is_wp_error($tweets_response)) {
            return $tweets_response;
        }
        
        return json_decode($tweets_response, true);
    }
    
    private function make_api_request($url, $params, $api_key, $api_secret, $access_token, $access_token_secret) {
        $oauth = array(
            'oauth_consumer_key' => $api_key,
            'oauth_nonce' => time(),
            'oauth_signature_method' => AFSX_OAUTH_SIGNATURE_METHOD,
            'oauth_timestamp' => time(),
            'oauth_token' => $access_token,
            'oauth_version' => AFSX_OAUTH_VERSION
        );
        
        $base_info = $this->build_base_string($url, 'GET', array_merge($oauth, $params));
        $composite_key = rawurlencode($api_secret) . '&' . rawurlencode($access_token_secret);
        $oauth_signature = base64_encode(hash_hmac('sha1', $base_info, $composite_key, true));
        $oauth['oauth_signature'] = $oauth_signature;
        
        $header = array($this->build_authorization_header($oauth), 'Expect:');
        
        $options = array(
            CURLOPT_HTTPHEADER => $header,
            CURLOPT_HEADER => true,
            CURLOPT_URL => $url . '?' . http_build_query($params),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
        );
        
        $start_time = microtime(true);
        $feed = curl_init();
        curl_setopt_array($feed, $options);
        $response = curl_exec($feed);
        $http_code = curl_getinfo($feed, CURLINFO_HTTP_CODE);
        $header_size = curl_getinfo($feed, CURLINFO_HEADER_SIZE);
        curl_close($feed);
        $end_time = microtime(true);
        
        // Separate headers and body
        $headers = substr($response, 0, $header_size);
        $json = substr($response, $header_size);
        
        // Log the API request
        $this->log_api_request($url, $http_code, $end_time - $start_time, $headers);
        
        if ($http_code !== 200) {
            $error_code = 'api_error';
            $error_message = 'API request failed with code: ' . $http_code;
            
            // Special handling for rate limiting
            if ($http_code === 429) {
                $error_code = 'api_error_429';
                $error_message = 'Rate limit exceeded. Please wait before making more requests.';
                
                // Extract rate limit headers if available
                if (preg_match('/x-rate-limit-remaining:\s*(\d+)/i', $headers, $matches)) {
                    $remaining = $matches[1];
                    if ($remaining == 0) {
                        if (preg_match('/x-rate-limit-reset:\s*(\d+)/i', $headers, $reset_matches)) {
                            $reset_time = $reset_matches[1];
                            $wait_time = $reset_time - time();
                            $error_message .= ' Rate limit resets in ' . max(1, $wait_time) . ' seconds.';
                        }
                    }
                }
            }
            
            return new WP_Error($error_code, $error_message);
        }
        
        return $json;
    }
    
    private function build_base_string($baseURI, $method, $params) {
        $r = array();
        ksort($params);
        foreach($params as $key => $value) {
            $r[] = "$key=" . rawurlencode($value);
        }
        return $method . "&" . rawurlencode($baseURI) . '&' . rawurlencode(implode('&', $r));
    }
    
    private function build_authorization_header($oauth) {
        $r = 'Authorization: OAuth ';
        $values = array();
        foreach($oauth as $key => $value) {
            $values[] = "$key=\"" . rawurlencode($value) . "\"";
        }
        $r .= implode(', ', $values);
        return $r;
    }
    
    private function log_api_request($url, $http_code, $response_time, $headers) {
        $logs = get_option(AFSX_LOG_OPTION, array());
        
        // Extract rate limit info from headers
        $rate_limit_remaining = null;
        $rate_limit_reset = null;
        if (preg_match('/x-rate-limit-remaining:\s*(\d+)/i', $headers, $matches)) {
            $rate_limit_remaining = (int)$matches[1];
        }
        if (preg_match('/x-rate-limit-reset:\s*(\d+)/i', $headers, $matches)) {
            $rate_limit_reset = (int)$matches[1];
        }
        
        $log_entry = array(
            'timestamp' => time(),
            'url' => $url,
            'http_code' => $http_code,
            'response_time' => round($response_time * 1000, 2), // Convert to milliseconds
            'rate_limit_remaining' => $rate_limit_remaining,
            'rate_limit_reset' => $rate_limit_reset,
        );
        
        // Add to beginning of array
        array_unshift($logs, $log_entry);
        
        // Keep only the most recent entries
        if (count($logs) > AFSX_MAX_LOG_ENTRIES) {
            $logs = array_slice($logs, 0, AFSX_MAX_LOG_ENTRIES);
        }
        
        update_option(AFSX_LOG_OPTION, $logs);
    }
    
    private function render_feed($feed_data) {
        if (!isset($feed_data['data']) || empty($feed_data['data'])) {
            return '<div class="afsx-error">No tweets found.</div>';
        }
        
        $output = '<div class="afsx-timeline">';
        
        $users = array();
        if (isset($feed_data['includes']['users'])) {
            foreach ($feed_data['includes']['users'] as $user) {
                $users[$user['id']] = $user;
            }
        }
        
        foreach ($feed_data['data'] as $tweet) {
            $user = isset($users[$tweet['author_id']]) ? $users[$tweet['author_id']] : null;
            $output .= $this->render_tweet($tweet, $user);
        }
        
        $output .= '</div>';
        
        return $output;
    }
    
    private function render_tweet($tweet, $user) {
        $created_at = new DateTime($tweet['created_at']);
        $formatted_date = $created_at->format('M j, Y');
        
        $profile_image = $user ? $user['profile_image_url'] : '';
        $display_name = $user ? $user['name'] : 'Unknown User';
        $username = $user ? '@' . $user['username'] : '';
        
        $text = $this->format_tweet_text($tweet['text']);
        
        $output = '<div class="afsx-tweet">';
        $output .= '<div class="afsx-tweet-header">';
        
        if ($profile_image) {
            $output .= '<img class="afsx-avatar" src="' . esc_url($profile_image) . '" alt="' . esc_attr($display_name) . '">';
        }
        
        $output .= '<div class="afsx-user-info">';
        $output .= '<div class="afsx-display-name">' . esc_html($display_name) . '</div>';
        $output .= '<div class="afsx-username">' . esc_html($username) . '</div>';
        $output .= '</div>';
        
        $output .= '<div class="afsx-date">' . esc_html($formatted_date) . '</div>';
        $output .= '</div>';
        
        $output .= '<div class="afsx-tweet-content">';
        $output .= '<div class="afsx-tweet-text">' . $text . '</div>';
        $output .= '</div>';
        
        if (isset($tweet['public_metrics'])) {
            $metrics = $tweet['public_metrics'];
            $output .= '<div class="afsx-tweet-metrics">';
            $output .= '<span class="afsx-metric"><span class="afsx-metric-count">' . number_format($metrics['like_count']) . '</span> likes</span>';
            $output .= '<span class="afsx-metric"><span class="afsx-metric-count">' . number_format($metrics['retweet_count']) . '</span> retweets</span>';
            $output .= '<span class="afsx-metric"><span class="afsx-metric-count">' . number_format($metrics['reply_count']) . '</span> replies</span>';
            $output .= '</div>';
        }
        
        $output .= '</div>';
        
        return $output;
    }
    
    private function format_tweet_text($text) {
        // Convert URLs to links
        $text = preg_replace('/(https?:\/\/[^\s]+)/', '<a href="$1" target="_blank" rel="noopener noreferrer">$1</a>', $text);
        
        // Convert @mentions to links
        $text = preg_replace('/@([A-Za-z0-9_]+)/', '<a href="' . AFSX_TWITTER_BASE_URL . '/$1" target="_blank" rel="noopener noreferrer">@$1</a>', $text);
        
        // Convert hashtags to links
        $text = preg_replace('/#([A-Za-z0-9_]+)/', '<a href="' . AFSX_TWITTER_BASE_URL . '/hashtag/$1" target="_blank" rel="noopener noreferrer">#$1</a>', $text);
        
        return $text;
    }
    
    public function add_admin_menu() {
        add_options_page(
            'AFSX Feed Settings',
            'AFSX Feed',
            AFSX_ADMIN_CAPABILITY,
            AFSX_ADMIN_MENU_SLUG,
            array($this, 'admin_page')
        );
    }
    
    public function admin_init() {
        register_setting(AFSX_SETTINGS_GROUP, AFSX_OPTION_API_KEY);
        register_setting(AFSX_SETTINGS_GROUP, AFSX_OPTION_API_SECRET);
        register_setting(AFSX_SETTINGS_GROUP, AFSX_OPTION_ACCESS_TOKEN);
        register_setting(AFSX_SETTINGS_GROUP, AFSX_OPTION_ACCESS_TOKEN_SECRET);
        
        add_settings_section(
            AFSX_SETTINGS_SECTION,
            'X API Credentials',
            array($this, 'settings_section_callback'),
            AFSX_SETTINGS_GROUP
        );
        
        add_settings_field(
            AFSX_OPTION_API_KEY,
            'API Key',
            array($this, 'api_key_callback'),
            AFSX_SETTINGS_GROUP,
            AFSX_SETTINGS_SECTION
        );
        
        add_settings_field(
            AFSX_OPTION_API_SECRET,
            'API Secret',
            array($this, 'api_secret_callback'),
            AFSX_SETTINGS_GROUP,
            AFSX_SETTINGS_SECTION
        );
        
        add_settings_field(
            AFSX_OPTION_ACCESS_TOKEN,
            'Access Token',
            array($this, 'access_token_callback'),
            AFSX_SETTINGS_GROUP,
            AFSX_SETTINGS_SECTION
        );
        
        add_settings_field(
            AFSX_OPTION_ACCESS_TOKEN_SECRET,
            'Access Token Secret',
            array($this, 'access_token_secret_callback'),
            AFSX_SETTINGS_GROUP,
            AFSX_SETTINGS_SECTION
        );
    }
    
    public function settings_section_callback() {
        echo '<p>Enter your X API credentials below. You can get these from the <a href="https://developer.twitter.com/en/apps" target="_blank">Twitter Developer Portal</a>.</p>';
    }
    
    public function api_key_callback() {
        $value = get_option(AFSX_OPTION_API_KEY);
        echo '<input type="text" name="' . AFSX_OPTION_API_KEY . '" value="' . esc_attr($value) . '" size="50" />';
    }
    
    public function api_secret_callback() {
        $value = get_option(AFSX_OPTION_API_SECRET);
        echo '<input type="text" name="' . AFSX_OPTION_API_SECRET . '" value="' . esc_attr($value) . '" size="50" />';
    }
    
    public function access_token_callback() {
        $value = get_option(AFSX_OPTION_ACCESS_TOKEN);
        echo '<input type="text" name="' . AFSX_OPTION_ACCESS_TOKEN . '" value="' . esc_attr($value) . '" size="50" />';
    }
    
    public function access_token_secret_callback() {
        $value = get_option(AFSX_OPTION_ACCESS_TOKEN_SECRET);
        echo '<input type="text" name="' . AFSX_OPTION_ACCESS_TOKEN_SECRET . '" value="' . esc_attr($value) . '" size="50" />';
    }
    
    public function admin_page() {
        // Handle cache clearing actions
        if (isset($_POST['clear_cache'])) {
            $this->clear_cache($_POST['cache_key']);
            echo '<div class="notice notice-success"><p>Cache cleared successfully.</p></div>';
        }
        if (isset($_POST['clear_all_cache'])) {
            $this->clear_all_cache();
            echo '<div class="notice notice-success"><p>All caches cleared successfully.</p></div>';
        }
        if (isset($_POST['clear_logs'])) {
            delete_option(AFSX_LOG_OPTION);
            echo '<div class="notice notice-success"><p>API logs cleared successfully.</p></div>';
        }
        
        ?>
        <div class="wrap">
            <h1>AFSX Feed Settings</h1>
            <form method="post" action="options.php">
                <?php
                settings_fields(AFSX_SETTINGS_GROUP);
                do_settings_sections(AFSX_SETTINGS_GROUP);
                submit_button();
                ?>
            </form>
            
            <div class="afsx-usage">
                <h3>Usage</h3>
                <p>Use the <code>[afsx]</code> shortcode to display X feeds:</p>
                <ul>
                    <li><code>[afsx username="twitter"]</code> - Display last 5 tweets from @twitter</li>
                    <li><code>[afsx username="twitter" count="10"]</code> - Display last 10 tweets</li>
                    <li><code>[afsx username="twitter" count="5" cache_time="600"]</code> - Cache for 10 minutes</li>
                </ul>
            </div>
            
            <?php $this->render_cache_status(); ?>
            
            <?php $this->render_debug_info(); ?>
            
            <?php $this->render_api_logs(); ?>
            
        </div>
        <?php
    }
    
    private function render_cache_status() {
        ?>
        <div class="afsx-cache-status">
            <h3>Cache Status</h3>
            <form method="post" style="display: inline;">
                <input type="submit" name="clear_all_cache" value="Clear All Cache" class="button" 
                       onclick="return confirm('Are you sure you want to clear all cached data?');" />
            </form>
            <table class="widefat">
                <thead>
                    <tr>
                        <th>Type</th>
                        <th>Key</th>
                        <th>Status</th>
                        <th>Age</th>
                        <th>Expires In</th>
                        <th>Last Tweet</th>
                        <th>Actions</th>
                    </tr>
                </thead>
                <tbody>
                    <?php $this->render_cache_entries(); ?>
                </tbody>
            </table>
        </div>
        <?php
    }
    
    private function render_cache_entries() {
        global $wpdb;
        
        // Get all transients that match our prefixes
        $transients = $wpdb->get_results(
            $wpdb->prepare(
                "SELECT option_name, option_value FROM {$wpdb->options} 
                 WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s
                 ORDER BY option_name",
                '_transient_' . AFSX_CACHE_PREFIX . '%',
                '_transient_' . AFSX_USER_CACHE_PREFIX . '%',
                '_transient_' . AFSX_ERROR_CACHE_PREFIX . '%'
            )
        );
        
        if (empty($transients)) {
            echo '<tr><td colspan="7">No cached data found.</td></tr>';
            return;
        }
        
        foreach ($transients as $transient) {
            $key = str_replace('_transient_', '', $transient->option_name);
            $data = maybe_unserialize($transient->option_value);
            
            $type = 'Feed';
            if (strpos($key, AFSX_USER_CACHE_PREFIX) === 0) {
                $type = 'User ID';
            } elseif (strpos($key, AFSX_ERROR_CACHE_PREFIX) === 0) {
                $type = 'Error';
            }
            
            // Get timeout
            $timeout_key = '_transient_timeout_' . $key;
            $timeout = get_option($timeout_key, 0);
            $expires_in = $timeout ? max(0, $timeout - time()) : 0;
            $age = $timeout ? time() - ($timeout - ($type === 'User ID' ? AFSX_USER_ID_CACHE_DURATION : ($type === 'Error' ? AFSX_ERROR_CACHE_DURATION : AFSX_DEFAULT_CACHE_DURATION))) : 'Unknown';
            
            $status = 'Valid';
            $last_tweet = 'N/A';
            
            if ($type === 'Error') {
                $status = 'Error Cached';
            } elseif ($type === 'Feed' && is_array($data) && isset($data['data'])) {
                if (!empty($data['data'])) {
                    $latest_tweet = $data['data'][0];
                    if (isset($latest_tweet['created_at'])) {
                        $last_tweet = date('M j, Y H:i', strtotime($latest_tweet['created_at']));
                    }
                } else {
                    $status = 'Empty Feed';
                }
            }
            
            echo '<tr>';
            echo '<td>' . esc_html($type) . '</td>';
            echo '<td><code>' . esc_html($key) . '</code></td>';
            echo '<td>' . esc_html($status) . '</td>';
            echo '<td>' . (is_numeric($age) ? human_time_diff($age, time()) . ' ago' : $age) . '</td>';
            echo '<td>' . ($expires_in > 0 ? human_time_diff(time(), time() + $expires_in) : 'Expired') . '</td>';
            echo '<td>' . esc_html($last_tweet) . '</td>';
            echo '<td>';
            echo '<form method="post" style="display: inline;">';
            echo '<input type="hidden" name="cache_key" value="' . esc_attr($key) . '" />';
            echo '<input type="submit" name="clear_cache" value="Clear" class="button-secondary" />';
            echo '</form>';
            echo '</td>';
            echo '</tr>';
        }
    }
    
    private function render_debug_info() {
        global $wpdb;
        ?>
        <div class="afsx-debug-info">
            <h3>Debug Information</h3>
            
            <h4>Cache Prefixes:</h4>
            <ul>
                <li><strong>Feed Cache:</strong> <code><?php echo AFSX_CACHE_PREFIX; ?></code></li>
                <li><strong>User Cache:</strong> <code><?php echo AFSX_USER_CACHE_PREFIX; ?></code></li>
                <li><strong>Error Cache:</strong> <code><?php echo AFSX_ERROR_CACHE_PREFIX; ?></code></li>
            </ul>
            
            <h4>All AFSX Transients in Database:</h4>
            <?php
            $all_transients = $wpdb->get_results(
                "SELECT option_name, option_value FROM {$wpdb->options} 
                 WHERE option_name LIKE '%afsx%' AND option_name LIKE '%transient%'
                 ORDER BY option_name"
            );
            
            if (empty($all_transients)) {
                echo '<p>No AFSX transients found in database.</p>';
            } else {
                echo '<table class="widefat" style="max-width: 800px;">';
                echo '<thead><tr><th>Option Name</th><th>Value Type</th><th>Size</th></tr></thead><tbody>';
                foreach ($all_transients as $transient) {
                    $value = maybe_unserialize($transient->option_value);
                    $type = gettype($value);
                    if ($type === 'object') {
                        $type .= ' (' . get_class($value) . ')';
                    }
                    $size = strlen($transient->option_value);
                    echo '<tr>';
                    echo '<td><code>' . esc_html($transient->option_name) . '</code></td>';
                    echo '<td>' . esc_html($type) . '</td>';
                    echo '<td>' . esc_html($size) . ' bytes</td>';
                    echo '</tr>';
                }
                echo '</tbody></table>';
            }
            ?>
            
            <h4>Recent Error Messages:</h4>
            <?php
            $logs = get_option(AFSX_LOG_OPTION, array());
            $errors = array_filter(array_slice($logs, 0, 5), function($log) {
                return $log['http_code'] >= 400;
            });
            
            if (empty($errors)) {
                echo '<p>No recent API errors.</p>';
            } else {
                foreach ($errors as $error) {
                    echo '<div style="background: #ffeaea; padding: 10px; margin: 5px 0; border-left: 4px solid #dc3232;">';
                    echo '<strong>HTTP ' . $error['http_code'] . '</strong> at ' . date('M j, H:i:s', $error['timestamp']);
                    echo '<br>Endpoint: <code>' . str_replace(AFSX_API_BASE_URL, '', $error['url']) . '</code>';
                    if ($error['rate_limit_remaining'] !== null) {
                        echo '<br>Rate Limit Remaining: ' . $error['rate_limit_remaining'];
                    }
                    echo '</div>';
                }
            }
            ?>
        </div>
        <?php
    }
    
    private function render_api_logs() {
        $logs = get_option(AFSX_LOG_OPTION, array());
        ?>
        <div class="afsx-api-logs">
            <h3>API Request Log</h3>
            <form method="post" style="display: inline;">
                <input type="submit" name="clear_logs" value="Clear Logs" class="button" 
                       onclick="return confirm('Are you sure you want to clear all API logs?');" />
            </form>
            <p>Showing last <?php echo count($logs); ?> requests (max <?php echo AFSX_MAX_LOG_ENTRIES; ?>):</p>
            
            <?php if (empty($logs)): ?>
                <p>No API requests logged yet.</p>
            <?php else: ?>
                <table class="widefat">
                    <thead>
                        <tr>
                            <th>Time</th>
                            <th>Endpoint</th>
                            <th>Status</th>
                            <th>Response Time</th>
                            <th>Rate Limit Remaining</th>
                            <th>Rate Limit Reset</th>
                        </tr>
                    </thead>
                    <tbody>
                        <?php foreach (array_slice($logs, 0, 20) as $log): ?>
                            <tr class="<?php echo $log['http_code'] >= 400 ? 'error-row' : 'success-row'; ?>">
                                <td><?php echo date('M j, H:i:s', $log['timestamp']); ?></td>
                                <td>
                                    <code><?php 
                                        $endpoint = str_replace(AFSX_API_BASE_URL, '', $log['url']);
                                        echo esc_html($endpoint);
                                    ?></code>
                                </td>
                                <td>
                                    <span class="status-<?php echo $log['http_code']; ?>">
                                        <?php echo $log['http_code']; ?>
                                    </span>
                                </td>
                                <td><?php echo $log['response_time']; ?>ms</td>
                                <td><?php echo $log['rate_limit_remaining'] !== null ? $log['rate_limit_remaining'] : 'N/A'; ?></td>
                                <td><?php 
                                    if ($log['rate_limit_reset']) {
                                        echo date('H:i:s', $log['rate_limit_reset']);
                                    } else {
                                        echo 'N/A';
                                    }
                                ?></td>
                            </tr>
                        <?php endforeach; ?>
                    </tbody>
                </table>
                
                <style>
                .error-row { background-color: #ffeaea; }
                .success-row { background-color: #eafff0; }
                .status-200 { color: green; font-weight: bold; }
                .status-429 { color: red; font-weight: bold; }
                .status-404 { color: orange; font-weight: bold; }
                </style>
            <?php endif; ?>
        </div>
        <?php
    }
    
    private function clear_cache($cache_key) {
        delete_transient($cache_key);
    }
    
    private function clear_all_cache() {
        global $wpdb;
        
        // Clear all AFSX transients
        $wpdb->query(
            $wpdb->prepare(
                "DELETE FROM {$wpdb->options} 
                 WHERE option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s
                    OR option_name LIKE %s OR option_name LIKE %s OR option_name LIKE %s",
                '_transient_' . AFSX_CACHE_PREFIX . '%',
                '_transient_timeout_' . AFSX_CACHE_PREFIX . '%',
                '_transient_' . AFSX_USER_CACHE_PREFIX . '%',
                '_transient_timeout_' . AFSX_USER_CACHE_PREFIX . '%',
                '_transient_' . AFSX_ERROR_CACHE_PREFIX . '%',
                '_transient_timeout_' . AFSX_ERROR_CACHE_PREFIX . '%'
            )
        );
    }
}

new AFSX_Feed();