<?php
/**
 * Login for Cloudflare Access Core
 *
 * @package Login for Cloudflare Access
 */

/**
 * Plugin component common to all versions of Login for Cloudflare Access
 */


use Auth0\SDK\Helpers\Tokens\AsymmetricVerifier;
use Auth0\SDK\Helpers\Tokens\IdTokenVerifier;
use CoderCat\JWKToPEM\JWKConverter;



class Core_Cloudflare_Access_Login {

	protected $options = null;
	/**
	 * Cookie Name.
	 *
	 * @var string
	 */
	protected static $gal_cookie_name = 'wordpress_cloudflare_access_login';
	protected static $option_prefix = "cfa_auth_";

	/**
	 * Class Constructor.
	 */
	protected function __construct() {
		$this->add_actions();
		register_activation_hook( $this->my_plugin_basename(), array( $this, 'cfa_activation_hook' ) );
	}

	/**
	 * Activation Hook
	 *
	 * @param bool $network_wide Is Network Wide.
	 * @return void
	 */
	public function cfa_activation_hook( $network_wide ) {
		global $gal_core_already_exists;
	}

	public function cfa_plugins_loaded() {
		//load_plugin_textdomain( 'google-apps-login', false, dirname( $this->my_plugin_basename() ) . '/lang/' );
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


	public function cfa_authenticate( $user, $username = null, $password = null ) {

		print_r($user);

		return $user;

	}



	public function cfa_login_form() {


		if (!isset($_COOKIE['CF_Authorization'])) {
			return;
		}

		error_log("CF_Authorization:".$_COOKIE['CF_Authorization']);


		try {
			$aud = "7452357e90afdefc3ff4d23782eca1079641046a54ee91ee7998425beac555b3";
			$issuer = "https://senseservices.cloudflareaccess.com";
  			$id_token = $_COOKIE['CF_Authorization'];
  			$key = $this->getKey($issuer . '/cdn-cgi/access/certs');
  			$signature_verifier = new AsymmetricVerifier($key);
  			$token_verifier = new IdTokenVerifier($issuer, $aud, $signature_verifier);
  			$user_identity = $token_verifier->verify($id_token);

			$user = get_user_by( 'email', $user_identity["email"] );
			if (!$user) {
				return;
			}


			$secure_cookie = is_ssl();

			// See wp_signon() for documentation on this filter.
			$secure_cookie = apply_filters(
				'secure_signon_cookie',
				$secure_cookie,
				[
					'user_login'    => $user->user_login,
					'user_password' => null,
					'remember'      => false
				]
			);

			wp_set_auth_cookie( $user->ID, false, $secure_cookie );
			do_action( 'wp_login', $user->user_login, $user );
			$redirect_to = empty( $_GET['redirect_to'] )
				? '/wp-admin/'
				: filter_var( wp_unslash( $_GET['redirect_to'] ), FILTER_SANITIZE_URL );

			$login_redirect = add_query_arg( time(), '', $redirect_to );
			wp_safe_redirect( $login_redirect );
			exit;


			//print_r($user);
		} catch (\Exception $e) {
			print "<pre>"; print $e->getMessage(); print "</pre>";
			return false;
		}

		//$token = json_decode(base64_decode(str_replace('_', '/', str_replace('-','+',explode('.', $_COOKIE['CF_Authorization'])[1]))));


	}






	 public function cfa_admin_menu() {
                        add_options_page(
                                __( 'Login for Cloudflare Zero Trust settings', 'cloudflare-access-login' ),
                                __( 'Login for Cloudflare Zero Trust', 'cloudflare-access-login' ),
                                'manage_options',
                                $this->get_options_menuname(),
                                array( $this, 'cfa_options_do_page' )
                        );
        }


        protected function get_options_menuname() {
                return 'cfalogin_list_options';
        }






	// Build our own nonce functions as wp_create_nonce is user dependent,
	// and our nonce is created when logged-out, then verified when logged-in






	 public function cfa_options_do_page() {
                if ( ! current_user_can( is_multisite() ? 'manage_network_options' : 'manage_options' ) ) {
                        wp_die();
                }


?>
		 <div>

                <h2><?php esc_html_e( 'Login for Cloudflare Zero Trust setup', 'cloudflare-access-login' ); ?></h2>
<?php

		$options = [
			[
				'name'     => 'Issuer',
				'opt'      => 'issuer',
				'id'       => 'issuer',
				'function' => 'render_issuer',
		]
		];

		$section_name="";
		$id="basic";
		$options_name = self::$option_prefix . strtolower( $id );
		$section_id   = "wp_auth0_{$id}_settings_section";

		add_settings_section(
			$section_id,
			"Basic Settings",
			null,
			$options_name
		);


		foreach ( $options as $setting ) {
			print_r($setting);
			$callback = function_exists( $setting['function'] )
				? $setting['function']
				: $this->$setting['function'];

			add_settings_field(
				$setting['id'],
				$setting['name'],
				$callback,
				$options_name,
				$section_id,
				[
					'label_for' => $setting['id'],
					'opt_name'  => isset( $setting['opt'] ) ? $setting['opt'] : null,
				]
			);
		}


	}

	const ERROR_FIELD_STYLE = 'border: 1px solid red;';


	protected function getOptions($base, $key = null) {

		if ($this->options === null) {
			$this->options=get_option($base, []);
		}

		return ($key!==null) ? ($this->options[$key] ?? null) : $key;
	}

	public function render_issuer( $args = [] ) {

		print_r($args); exit;

		$style = $this->getOptions->get( $args['opt_name'] ) ? '' : self::ERROR_FIELD_STYLE;
		$this->render_text_field( $args['label_for'], $args['opt_name'], 'text', 'your-tenant.auth0.com', $style );
		$this->render_field_description(
			__( 'Auth0 Domain, found in your Application settings in the ', 'wp-auth0' ) .
			$this->get_dashboard_link( 'applications' )
		);
	}

	protected function render_field_description( $text ) {
		$period = ! in_array( $text[ strlen( $text ) - 1 ], [ '.', ':' ] ) ? '.' : '';
		printf( '<div class="subelement"><span class="description">%s%s</span></div>', $text, $period );
	}

	protected function render_text_field( $id, $input_name, $type = 'text', $placeholder = '', $style = '', $grouping = '' ) {

		// Secure fields are not output by default; validation keeps last value if a new one is not entered
		if ( 'password' === $type ) {
			$value = empty( $value ) ? '' : __( '[REDACTED]', 'wp-auth0' );
			$type  = 'text';
		}
		if ( $field_is_const = $this->options->has_constant_val( $input_name ) ) {
			$this->render_const_notice( $input_name );
		}
		printf(
			'<input data-group="%s" type="%s" name="%s[%s]" id="%s" value="%s" placeholder="%s" style="%s" %s>',
			esc_attr( $grouping ),
			esc_attr( $type ),
			esc_attr( $this->_option_name ),
			esc_attr( $input_name ),
			esc_attr( $id ),
			esc_attr( $value ),
			$placeholder ? esc_attr( $placeholder ) : '',
			$style ? esc_attr( $style ) : '',
			$field_is_const ? 'disabled' : ''
		);
	}






	// HOOKS AND FILTERS
	// *****************

	protected function add_actions() {
		//add_action( 'plugins_loaded', array( $this, 'cfa_plugins_loaded' ) );

		//add_action( 'login_enqueue_scripts', array( $this, 'cfa_login_styles' ) );
		add_action( 'login_form', array( $this, 'cfa_login_form' ), 1 );
		add_filter( 'authenticate', array( $this, 'cfa_authenticate' ), 5, 3 );

		//add_filter( 'login_redirect', array( $this, 'cfa_login_redirect' ), 5, 3 );
		//add_action( 'init', array( $this, 'cfa_init' ), 1 );

		//add_action( 'admin_init', array( $this, 'cfa_admin_init' ), 5, 0 );

		add_action( 'admin_menu', array( $this, 'cfa_admin_menu' ) );

		//add_filter( 'gal_get_clientid', array( $this, 'gal_get_clientid' ) );

		//add_action( 'upgrader_process_complete', array( $this, 'my_upgrade_function' ), 10, 2 );
/*
		if ( is_multisite() ) {
			add_filter( 'network_admin_plugin_action_links', array( $this, 'cfa_plugin_action_links' ), 10, 2 );
			add_action( 'network_admin_edit_' . $this->get_options_menuname(), array( $this, 'cfa_save_network_options' ) );
		} else {
			add_filter( 'plugin_action_links', array( $this, 'cfa_plugin_action_links' ), 10, 2 );
		} */
	}




}

class CFA_Service_Exception extends Exception {} // @codingStandardsIgnoreLine
