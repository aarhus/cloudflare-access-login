<?php

function gal_service_account_upgrade( &$option, $gal_option_name, &$existing_sa_options, $gal_sa_option_name ) {
	/*
	 Convert cfa_serviceemail cfa_keyfilepath
	* into new separate sa options:
	* cfa_sakey, cfa_serviceemail, cfa_pkey_print
	*/

	if ( count( $existing_sa_options ) ) {
		return;
	}

	$existing_sa_options = array(
		'cfa_serviceemail' => isset( $option['cfa_serviceemail'] ) ? $option['cfa_serviceemail'] : '',
		'cfa_sakey'        => '',
		'cfa_pkey_print'   => '<unspecified>',
	);

	try {
		if ( version_compare( PHP_VERSION, '5.3.0' ) >= 0 && function_exists( 'openssl_x509_read' ) ) {
			if ( isset( $option['cfa_keyfilepath'] ) && '' !== $option['cfa_keyfilepath'] && file_exists( $option['cfa_keyfilepath'] ) ) {
				$p12key = @file_get_contents( $option['cfa_keyfilepath'] );

				$certs = array();
				if ( openssl_pkcs12_read( $p12key, $certs, 'notasecret' ) ) {
					if ( array_key_exists( 'pkey', $certs ) && $certs['pkey'] ) {
						$privateKey = openssl_pkey_get_private( $certs['pkey'] );
						$pemString  = '';
						if ( openssl_pkey_export( $privateKey, $pemString ) ) {
							$existing_sa_options['cfa_sakey'] = $pemString;
						}
						openssl_pkey_free( $privateKey );

						@unlink( $options['cfa_keyfilepath'] );
					}
				}
			}
		}
	} catch ( Exception $e ) {
		return;
	}

	// Remove redundant parts of regular options
	unset( $option['cfa_serviceemail'] );
	unset( $option['cfa_keyfilepath'] );
}
