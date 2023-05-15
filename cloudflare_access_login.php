<?php
/**
 * Plugin Name: Login for Cloudflare Access
 * Plugin URI: https://github.com/aarhus/cloudflare-access-login
 * Description: Simple secure login for WordPress through users' Cloudflare Access accounts (uses secure OAuth2, and MFA if enabled)
 * Version: 3.4.5
 * Author: aarhus
 * Author URI: https://ko-fi.com/aarhus
 * License: GPL3
 * Network: true
 * Text Domain: cloudflare-access-login
 * Domain Path: /lang
 */

$path = rtrim( plugin_dir_path( __FILE__ ), '/\\' );
require_once $path . '/vendor/autoload.php';
require_once plugin_dir_path( __FILE__ ) . '/core/core_cloudflare_access_login.php';

class Basic_Cloudflare_Access_Login extends Core_Cloudflare_Access_Login {

	protected $plugin_version = '3.4.5';

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
	public static function get_instance() {
		if ( null === self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Activation Hook.
	 *
	 * @param bool $network_wide Is Network Wide.
	 *
	 * @return void
	 */

	protected function add_actions() {
		parent::add_actions();
		add_action( 'wp_ajax_gal_drip_submitted', array( $this, 'gal_drip_submitted' ) );
	}

	protected function cfa_section_text_end() {
		?>
		<p><b><?php esc_html_e( 'For full support, and premium features that greatly simplify WordPress user management for admins, please visit:', 'google-apps-login' ); ?>
		<a href="https://wp-glogin.com/glogin/?utm_source=Admin%20Promo&utm_medium=freemium&utm_campaign=Freemium" target="_blank">https://wp-glogin.com/</a></b>
		</p>
		<?php
	}

	protected function cfa_options_do_sidebar() {
		$drivelink   = 'https://wp-glogin.com/drive/?utm_source=Admin%20Sidebar&utm_medium=freemium&utm_campaign=Drive';
		$upgradelink = 'https://wp-glogin.com/glogin/?utm_source=Admin%20Sidebar&utm_medium=freemium&utm_campaign=Freemium';
		$avatarslink = 'https://wp-glogin.com/avatars/?utm_source=Admin%20Sidebar&utm_medium=freemium&utm_campaign=Avatars';
		$aioilink    = 'https://wp-glogin.com/intranet/?utm_source=Admin%20Sidebar&utm_medium=freemium&utm_campaign=AIOI';

		$adverts = array();

		$adverts[] = '<div>'
		. '<a href="' . esc_url( $upgradelink ) . '" target="_blank">'
		. '<img alt="Login upgrade" src="' . esc_url( $this->my_plugin_url() ) . 'img/basic_loginupgrade.png" />'
		. '</a>'
		. '<span>Buy our <a href="' . esc_url( $upgradelink ) . '" target="_blank">premium Login plugin</a> to revolutionize user management</span>'
		. '</div>';

		$adverts[] = '<div>'
		. '<a href="' . esc_url( $drivelink ) . '" target="_blank">'
		. '<img alt="Google Drive Embedder Plugin" src="' . esc_url( $this->my_plugin_url() ) . 'img/basic_driveplugin.png" />'
		. '</a>'
		. '<span>Try our <a href="' . esc_url( $drivelink ) . '" target="_blank">Google Drive Embedder</a> plugin</span>'
		. '</div>';

		$adverts[] = '<div>'
		. '<a href="' . esc_url( $avatarslink ) . '" target="_blank">'
		. '<img alt="Google Profile Avatars Plugin" src="' . esc_url( $this->my_plugin_url() ) . 'img/basic_avatars.png" />'
		. '</a>'
		. '<span>Bring your site to life with <a href="' . esc_url( $avatarslink ) . '" target="_blank">Google Profile Avatars</a></span>'
		. '</div>';

		$adverts[] = '<div>'
		. '<a href="' . esc_url( $aioilink ) . '" target="_blank">'
		. '<img alt="All-In-One Intranet Plugin" src="' . esc_url( $this->my_plugin_url() ) . 'img/basic_aioi.png" />'
		. '</a>'
		. '<span>Instantly turn WordPress into a corporate intranet with <a href="' . $aioilink . '" target="_blank">All-In-One Intranet</a></span>'
		. '</div>';

		$startnum = (int) gmdate( 'j' );

		echo '<div id="gal-tableright" class="gal-tablecell">';

		$this->output_drip_form();

		for ( $i = 0; $i < 2; $i++ ) {
			echo $adverts[ ( $startnum + $i ) % 4 ]; // @codingStandardsIgnoreLine
		}

		echo '</div>';

	}

	protected function output_drip_form() {
		$userdata = wp_get_current_user();
		if ( ! $userdata ) {
			return;
		}
		$signedup = get_user_meta( $userdata->ID, 'gal_user_signedup_to_drip', true );

		if ( ! $signedup ) {

			$useremail = $userdata->user_email;

			?>
			<div>
				<form action="https://www.getdrip.com/forms/9468024/submissions" method="post" target="_blank" data-drip-embedded-form="9468024" id="gal-drip-signup-form">
					<h3 data-drip-attribute="headline">Get the most out of Cloudflare Access and WordPress</h3>
					<p data-drip-attribute="description">
						Register your email address to receive information on building a WordPress site
						that truly integrates G Suite and WordPress.
					</p>
					<div>
						<label for="fields[email]">Email Address</label>
						<br />
						<input type="email" name="fields[email]" value="<?php echo esc_js( $useremail ); ?>" />
						<br />
						<input type="submit" name="submit" value="Sign Up" data-drip-attribute="sign-up-button" class="gal-drip-signup-button" />
					</div>
					<p class="gal-drip-unsubscribe">
						You can unsubscribe at any time, and we will never share your email address.
					</p>
				</form>
			</div>
			<?php
		}
	}

	public function gal_drip_submitted() {
		$userdata = wp_get_current_user();
		if ( ! $userdata ) {
			return;
		}
		update_user_meta( $userdata->ID, 'gal_user_signedup_to_drip', true );
	}

	protected function set_other_admin_notices() {
		global $pagenow;
		if ( in_array( $pagenow, array( 'users.php', 'user-new.php' ), true ) ) {
			$no_thanks = get_user_meta( get_current_user_id(), $this->get_options_name() . '_no_thanks', true );
			if ( ! $no_thanks ) {
				if ( isset( $_REQUEST['cloudflare_access_login_action'] ) && 'no_thanks' === $_REQUEST['cloudflare_access_login_action'] ) {
					$this->cfa_said_no_thanks( null );
				}

			}
		}
	}

	public function cfa_said_no_thanks( $data ) {
		update_user_meta( get_current_user_id(), $this->get_options_name() . '_no_thanks', true );
		wp_safe_redirect( remove_query_arg( 'cloudflare_access_login_action' ) );
		exit;
	}


	public function my_plugin_basename() {
		$basename = plugin_basename( __FILE__ );
		if ( __FILE__ === '/' . $basename ) { // Maybe due to symlink.
			$basename = basename( dirname( __FILE__ ) ) . '/' . basename( __FILE__ );
		}
		return $basename;
	}

	protected function my_plugin_url() {
		$basename = plugin_basename( __FILE__ );
		if ( __FILE__ === '/' . $basename ) { // Maybe due to symlink.
			return plugins_url() . '/' . basename( dirname( __FILE__ ) ) . '/';
		}

		// Normal case (non symlink).
		return plugin_dir_url( __FILE__ );
	}

}

/**
 * Plugin Init Method
 *
 * @return object
 */
function gal_basic_cloudflare_access_login() {
	return Basic_Cloudflare_Access_Login::get_instance();
}

// Initialise at least once.
gal_basic_cloudflare_access_login();

if ( ! function_exists( 'cloudflare_access_login' ) ) {
	/**
	 * Plugin Init Method
	 *
	 * @return object
	 */
	function cloudflare_access_login() {
		return gal_basic_cloudflare_access_login();
	}
}
