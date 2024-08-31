<?php
/**
 * Plugin Name: Admin Login for Cloudflare Access
 * Plugin URI: https://github.com/aarhus/cloudflare-access-login
 * Description: Simple secure login for WordPress through users' Cloudflare Access accounts (uses secure OAuth2, and MFA if enabled)
 * Version: 0.0.1
 * Author: aarhus
 * Author URI: https://ko-fi.com/aarhus
 * License: GPL3
 * Network: true
 * Text Domain: admin-login-for-cloudflare
 * Domain Path: /lang
 */

$path = rtrim(plugin_dir_path(__FILE__), '/\\');
require_once $path . '/vendor/autoload.php';
//require_once plugin_dir_path(__FILE__) . '/core/core_cloudflare_access_login.php';

use Firebase\JWT\JWK;
use Firebase\JWT\JWT;


class LFCFA_Cloudflare_Access_Login
{

    protected $options = null;
    /**
     * Cookie Name.
     *
     * @var string
     */
    protected static $option_prefix = "lfcfa_auth_";

    /**
     * Class Constructor.
     */
    protected function __construct()
    {
        $this->addActions();
    }

    public function lfcfa_add_plugin_page()
    {
        add_menu_page(
            __('Admin Login for Cloudflare Zero Trust settings', 'cloudflare-access-login'),
            __('Admin Login for Cloudflare Zero Trust', 'cloudflare-access-login'),
            'manage_options', // capability
            'wibble', // menu_slug
            array( $this, 'lfcfa_create_admin_page' ), // function
            'dashicons-admin-generic', // icon_url
            2 // position
        );
    }

    public function lfcfa_create_admin_page()
    {
        $this->lfcfa_options = get_option('lfcfa_option_name');
        ?>

        <div class="wrap">
        <h2>Login for Cloudflare Zero Trust</h2>
            <p>Automatically login to your Wordpress instance by putting your /wp-admin folder behind Cloudflare Zero Trust.  </p>
            <p>You can set this up as a <a href="https://developers.cloudflare.com/cloudflare-one/applications/configure-apps/self-hosted-apps/" target="_blank"> self-hosted application in Cloudflare Access</a>, and then use the settings below to configure this plugin.</p>
            <p>The audience field is found on the in the Cloudflare Access dashboard - browse to Application and visit the overview.  It is labeled as "Application Audience (AUD) Tag"
            <p>The issuer is in the format of "&lt;your-team-name&gt;.cloudflareaccess.com"</p>
        <?php settings_errors(); ?>

            <form method="post" action="options.php">
        <?php
        settings_fields('lfcfa_option_group');
        do_settings_sections('wibble-admin');
        submit_button();
        ?>
            </form>

            Get help by visiting our <a href="https://github.com/aarhus/cloudflare-access-login" target="_blank">Github Repository</a> or if you would like to support the plugin visit <a href="https://ko-fi.com/aarhus" target="_blank"></a>my Ko-fi page</a>

        </div>
    <?php }

    public function lfcfa_page_init()
    {
        register_setting(
            'lfcfa_option_group', // option_group
            'lfcfa_option_name', // option_name
            array( $this, 'lfcfa_sanitize' ) // sanitize_callback
        );

        add_settings_section(
            'lfcfa_setting_section', // id
            'Settings', // title
            array( $this, 'lfcfa_section_info' ), // callback
            'wibble-admin' // page
        );

        add_settings_field(
            'audience', // id
            'Audience', // title
            array( $this, 'audience_callback' ), // callback
            'wibble-admin', // page
            'lfcfa_setting_section' // section
        );

        add_settings_field(
            'issuer', // id
            'Issuer', // title
            array( $this, 'issuer_callback' ), // callback
            'wibble-admin', // page
            'lfcfa_setting_section' // section
        );
    }

    public function lfcfa_sanitize($input)
    {
        $sanitary_values = array();
        if (isset($input['audience']) ) {
            $sanitary_values['audience'] = sanitize_text_field($input['audience']);
        }

        if (isset($input['issuer']) ) {
            $sanitary_values['issuer'] = sanitize_text_field($input['issuer']);
        }

        return $sanitary_values;
    }

    public function lfcfa_section_info()
    {
        return "Here are some settings....";
    }

    public function audience_callback()
    {
        printf(
            '<input class="regular-text" type="text" name="lfcfa_option_name[audience]" id="audience" value="%s">',
            isset($this->lfcfa_options['audience']) ? esc_attr($this->lfcfa_options['audience']) : ''
        );
    }

    public function issuer_callback()
    {
        printf(
            '<input class="regular-text" type="text" name="lfcfa_option_name[issuer]" id="issuer" value="%s">',
            isset($this->lfcfa_options['issuer']) ? esc_attr($this->lfcfa_options['issuer']) : ''
        );
    }

    protected function getKey($jwksUrl)
    {

        if ( false === ( $rtn = get_transient( 'lfcfa_validator_key_cache' ) ) ) {

            // Key file is not cached so need to retrieve it

            $client = new GuzzleHttp\Client();
            $res = $client->request('GET', $jwksUrl);

            if ($res->getStatusCode() != '200') {
                return null;
            }

            try {
                $json = $res->getBody();
                $rtn = json_decode($json, true);


                set_transient( "lfcfa_validator_key_cache", $rtn, HOUR_IN_SECONDS );

            }
            catch (\Exception $e) {
                return null;
            }
        }
        return $rtn;
    }

    private function lfcfa_sanitize_jwt($input) {
        $matches = [];
        $a = preg_match("/^[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$/", $input, $matches);
        return ($matches ? $input : null);
    }

    public function lfcfaLoginForm()
    {

        if (!isset($_COOKIE['CF_Authorization'])) {
            return;
        }

        try {
            $opt = get_option('lfcfa_option_name');
            if (!isset($opt["issuer"]) || !isset($opt["audience"])) {
                return;
            }
            $id_token = $this->lfcfa_sanitize_jwt($_COOKIE['CF_Authorization']);

            if ($id_token === null) {

                return;
            }

            $keySet = $this->getKey("https://".$opt["issuer"] . '.cloudflareaccess.com/cdn-cgi/access/certs');

            if ($keySet === null) {
                return;
            }


            $decoded = JWT::decode(
                $id_token,
                JWK::parseKeySet($keySet)
            );


            if (!$decoded->email) {
                return;
            }


            $user = get_user_by('email', $decoded->email);
            if (!$user) {
                return;
            }


            $secure_cookie = is_ssl();

            $secure_cookie = apply_filters(
                'secure_signon_cookie',
                $secure_cookie,
                [
                'user_login'    => $user->user_login,
                'user_password' => null,
                'remember'      => false
                ]
            );

            wp_set_auth_cookie($user->ID, false, $secure_cookie);
            do_action('wp_login', $user->user_login, $user);
            $redirect_to = filter_var(wp_unslash($_GET['redirect_to']), FILTER_SANITIZE_URL);

            if (strlen($redirect_to)==0) {
                $redirect_to='/wp-admin/';
            }

            $login_redirect = add_query_arg(time(), '', $redirect_to);
            wp_safe_redirect($login_redirect);
            exit;

        } catch (\Exception $e) {
            print "Failed to validate your access as something went wrong";
            return false;
        }

    }

    // Create wordpress admin menu to collect the audience and issuer settings

    public function lfcfa_admin_menu()
    {
        add_options_page(
            __('Admin Login for Cloudflare Zero Trust settings', 'cloudflare-access-login'),
            __('Admin Login for Cloudflare Zero Trust', 'cloudflare-access-login'),
            'manage_options',
            'lfcfalogin_list_options',
            array( $this, 'lfcfa_create_admin_page' )
        );

    }

    // Build our own nonce functions as wp_create_nonce is user dependent,
    // and our nonce is created when logged-out, then verified when logged-in

    const ERROR_FIELD_STYLE = 'border: 1px solid red;';

    // HOOKS AND FILTERS
    // *****************

    protected function addActions()
    {
        add_action('login_form', array( $this, 'lfcfaLoginForm' ), 1);
        add_action(is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'lfcfa_admin_menu' ));
        add_action('admin_init', array( $this, 'lfcfa_page_init' ));

    }

    protected $plugin_version = '0.0.1';

    /**
     * Singleton Var
     *
     * @var object|self
     */
    private static $instance = null;

    /**
     * Singleton
     *
     * @return object
     */
    public static function get_instance()
    {
        if (null === self::$instance ) {
            self::$instance = new self();
        }
        return self::$instance;
    }



}

/**
 * Plugin Init Method
 *
 * @return object
 */
function lfcfa_cloudflare_access_login()
{
    return LFCFA_Cloudflare_Access_Login::get_instance();
}

// Initialise at least once.

lfcfa_cloudflare_access_login();
