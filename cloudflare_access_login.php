<?php
/**
 * Plugin Name: Login for Cloudflare Access
 * Plugin URI: https://github.com/aarhus/cloudflare-access-login
 * Description: Simple secure login for WordPress through users' Cloudflare Access accounts (uses secure OAuth2, and MFA if enabled)
 * Version: 0.0.1
 * Author: aarhus
 * Author URI: https://ko-fi.com/aarhus
 * License: GPL3
 * Network: true
 * Text Domain: cloudflare-access-login
 * Domain Path: /lang
 */

$path = rtrim(plugin_dir_path(__FILE__), '/\\');
require_once $path . '/vendor/autoload.php';
//require_once plugin_dir_path(__FILE__) . '/core/core_cloudflare_access_login.php';

use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\IdTokenVerifier;
use CoderCat\JWKToPEM\JWKConverter;

class CFA_Cloudflare_Access_Login
{

    protected $options = null;
    /**
     * Cookie Name.
     *
     * @var string
     */
    protected static $option_prefix = "cfa_auth_";

    /**
     * Class Constructor.
     */
    protected function __construct()
    {
        $this->addActions();
    }

    public function cfa_add_plugin_page()
    {
        add_menu_page(
            __('Login for Cloudflare Zero Trust settings', 'cloudflare-access-login'),
            __('Login for Cloudflare Zero Trust', 'cloudflare-access-login'),
            'manage_options', // capability
            'wibble', // menu_slug
            array( $this, 'cfa_create_admin_page' ), // function
            'dashicons-admin-generic', // icon_url
            2 // position
        );
    }

    public function cfa_create_admin_page()
    {
        $this->cfa_options = get_option('cfa_option_name');
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
        settings_fields('cfa_option_group');
        do_settings_sections('wibble-admin');
        submit_button();
        ?>
            </form>

            Get help by visiting our <a href="https://github.com/aarhus/cloudflare-access-login" target="_blank">Github Repository</a> or if you would like to support the plugin visit <a href="https://ko-fi.com/aarhus" target="_blank"></a>my Ko-fi page</a>

        </div>
    <?php }

    public function cfa_page_init()
    {
        register_setting(
            'cfa_option_group', // option_group
            'cfa_option_name', // option_name
            array( $this, 'cfa_sanitize' ) // sanitize_callback
        );

        add_settings_section(
            'cfa_setting_section', // id
            'Settings', // title
            array( $this, 'cfa_section_info' ), // callback
            'wibble-admin' // page
        );

        add_settings_field(
            'audience', // id
            'Audience', // title
            array( $this, 'audience_callback' ), // callback
            'wibble-admin', // page
            'cfa_setting_section' // section
        );

        add_settings_field(
            'issuer', // id
            'Issuer', // title
            array( $this, 'issuer_callback' ), // callback
            'wibble-admin', // page
            'cfa_setting_section' // section
        );
    }

    public function cfa_sanitize($input)
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

    public function cfa_section_info()
    {
        return "Here are some settings....";
    }

    public function audience_callback()
    {
        printf(
            '<input class="regular-text" type="text" name="cfa_option_name[audience]" id="audience" value="%s">',
            isset($this->cfa_options['audience']) ? esc_attr($this->cfa_options['audience']) : ''
        );
    }

    public function issuer_callback()
    {
        printf(
            '<input class="regular-text" type="text" name="cfa_option_name[issuer]" id="issuer" value="%s">',
            isset($this->cfa_options['issuer']) ? esc_attr($this->cfa_options['issuer']) : ''
        );
    }

    protected function getKey($jwksUrl)
    {


        $client = new GuzzleHttp\Client();
        $res = $client->request('GET', $jwksUrl);

        if ($res->getStatusCode() != '200') {
            throw new \Exception('Could not fetch JWKS');
        }

        $json = $res->getBody();
        $jwks = json_decode($json);

        $rtn = [];
        foreach ($jwks->keys as $k) {

            $key_id = $k->kid;

            $jwkConverter = new JWKConverter();
            $key = $jwkConverter->toPEM((array) $k);
            $rtn[$key_id] = $key;
        }
        return $rtn;
    }

    private function cfa_sanitize_jwt($input) {
        $matches = [];
        $a = preg_match("/^[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+\.[a-zA-Z0-9-_]+$/", $input, $matches);
        return ($matches ? $input : null);
    }

    public function cfaLoginForm()
    {

        if (!isset($_COOKIE['CF_Authorization'])) {
            return;
        }

        try {
            $opt = get_option('cfa_option_name');
            if (!isset($opt["issuer"]) || !isset($opt["audience"])) {
                return false;
            }
            $id_token = $this->cfa_sanitize_jwt($_COOKIE['CF_Authorization']);

            if ($id_token === null) {

                return;
            }
            $key = $this->getKey("https://".$opt["issuer"] . '.cloudflareaccess.com/cdn-cgi/access/certs');
            $signature_verifier = new AsymmetricVerifier($key);

            $token_verifier = new IdTokenVerifier("https://".$opt["issuer"].'.cloudflareaccess.com', $opt["audience"], $signature_verifier);
            $user_identity = $token_verifier->verify($id_token);

            $user = get_user_by('email', $user_identity["email"]);
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
            print "<pre>"; print $e->getMessage(); print "</pre>";
            return false;
        }

    }

    // Create wordpress admin menu to collect the audience and issuer settings

    public function cfa_admin_menu()
    {
        add_options_page(
            __('Login for Cloudflare Zero Trust settings', 'cloudflare-access-login'),
            __('Login for Cloudflare Zero Trust', 'cloudflare-access-login'),
            'manage_options',
            'cfalogin_list_options',
            array( $this, 'cfa_create_admin_page' )
        );

    }

    // Build our own nonce functions as wp_create_nonce is user dependent,
    // and our nonce is created when logged-out, then verified when logged-in

    const ERROR_FIELD_STYLE = 'border: 1px solid red;';

    // HOOKS AND FILTERS
    // *****************

    protected function addActions()
    {
        add_action('login_form', array( $this, 'cfaLoginForm' ), 1);
        add_action(is_multisite() ? 'network_admin_menu' : 'admin_menu', array( $this, 'cfa_admin_menu' ));
        add_action('admin_init', array( $this, 'cfa_page_init' ));

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
function cfa_cloudflare_access_login()
{
    return CFA_Cloudflare_Access_Login::get_instance();
}

// Initialise at least once.

cfa_cloudflare_access_login();
