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
define('AFSX_DEFAULT_CACHE_DURATION', 300); // 5 minutes in seconds
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
        $cached_data = get_transient($cache_key);
        
        if ($cached_data !== false) {
            return $cached_data;
        }
        
        $feed_data = $this->fetch_x_feed($username, $count);
        
        if (!is_wp_error($feed_data)) {
            set_transient($cache_key, $feed_data, $cache_time);
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
        
        $url = AFSX_API_BASE_URL . '/users/by/username/' . $username;
        
        // First, get user ID
        $user_response = $this->make_api_request($url, array(), $api_key, $api_secret, $access_token, $access_token_secret);
        
        if (is_wp_error($user_response)) {
            return $user_response;
        }
        
        $user_data = json_decode($user_response, true);
        
        if (!isset($user_data['data']['id'])) {
            return new WP_Error('user_not_found', 'User not found: ' . $username);
        }
        
        $user_id = $user_data['data']['id'];
        
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
            CURLOPT_HEADER => false,
            CURLOPT_URL => $url . '?' . http_build_query($params),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_SSL_VERIFYPEER => false,
        );
        
        $feed = curl_init();
        curl_setopt_array($feed, $options);
        $json = curl_exec($feed);
        $http_code = curl_getinfo($feed, CURLINFO_HTTP_CODE);
        curl_close($feed);
        
        if ($http_code !== 200) {
            return new WP_Error('api_error', 'API request failed with code: ' . $http_code);
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
        </div>
        <?php
    }
}

new AFSX_Feed();