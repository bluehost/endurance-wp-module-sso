<?php

if ( function_exists( 'add_action' ) ) {
	add_action( 'after_setup_theme', 'eig_module_sso_register' );
}

/**
 * Register the single sign-on module
 */
function eig_module_sso_register() {
	eig_register_module( array(
		'name'     => 'sso',
		'label'    => __( 'Single Sign-on', 'endurance' ),
		'callback' => 'eig_module_sso_load',
		'isActive' => true,
		'isHidden' => true,
	) );
}

/**
 * Load the single sign-on module
 */
function eig_module_sso_load() {

	require dirname( __FILE__ ) . '/functions.php';

	// Unregister actions from the sso.php mu-plugin in case they exist
	// This ensures that this code always takes priority for SSO handling
	remove_action( 'wp_ajax_nopriv_sso-check', 'sso_check' );
	remove_action( 'wp_ajax_sso-check', 'sso_check' );

	add_action( 'wp_ajax_nopriv_sso-check', 'eig_sso_handler' );
	add_action( 'wp_ajax_sso-check', 'eig_sso_handler' );

}
