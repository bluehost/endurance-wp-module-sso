<?php

if ( ! function_exists( 'eig_sso_handler' ) ) {

	/**
	 * Run SSO check and login if request is valid.
	 */
	function eig_sso_handler() {

		$nonce = filter_input( INPUT_GET, 'nonce', FILTER_SANITIZE_STRING );
		$salt = filter_input( INPUT_GET, 'salt', FILTER_SANITIZE_STRING );

		// Not doing SSO
		if ( ! $nonce || ! $salt ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Too many failed SSO attempts
		$attempts = eig_sso_failed_attempts();
		if ( $attempts > 4 ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Unable to get user
		$user = eig_sso_get_user();
		if ( ! $user ) {
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Invalid SSO token
		$hash = substr( base64_encode( hash( 'sha256', $nonce . $salt, false ) ), 0, 64 );
		if ( get_transient( 'sso_token' ) !== $hash ) {
			eig_sso_failed_attempts( 1 );
			wp_safe_redirect( wp_login_url() );
			exit;
		}

		// Log user in
		eig_sso_login_user( $user );

		// Redirect to desired location
		$redirect = esc_url( filter_input( INPUT_GET, 'bounce' ) );
		if ( $redirect ) {
			wp_safe_redirect( admin_url( $redirect ) );
			exit;
		}

		// If no desired location, redirect to Bluehost dashboard in WordPress by default.
		$redirect = apply_filters( 'eig_sso_default_redirect', admin_url( '/admin.php?page=mojo-home' ) );
		wp_safe_redirect( $redirect );

	}

}

if ( ! function_exists( 'eig_sso_failed_attempts' ) ) {

	/**
	 * Get and/or increment failed SSO attempts.
	 *
	 * @param int $increment
	 *
	 * @return int
	 */
	function eig_sso_failed_attempts( $increment = 0 ) {
		static $attempts;

		$key = 'sso_failures';
		if ( ! isset( $attempts ) ) {
			$attempts = absint( get_transient( $key ) );
		}
		if ( $increment ) {
			$attempts += $increment;
			set_transient( $key, $attempts, MINUTE_IN_SECONDS * 5 );
		}

		return $attempts;
	}

}

if ( ! function_exists( 'eig_sso_get_user' ) ) {

	/**
	 * Get the user for SSO.
	 *
	 * @return WP_User|false
	 */
	function eig_sso_get_user() {
		$user = false;
		$user_reference = filter_input( INPUT_GET, 'user' );

		if ( $user_reference ) {
			if ( is_email( $user_reference ) ) {
				$user = get_user_by( 'email', sanitize_email( $user_reference ) );
			} else {
				$user_id = absint( $user_reference );
				if ( $user_id ) {
					$user = get_user_by( 'id', $user_id );
				}
			}
		}

		// If no user reference or user not found, find first admin user
		if ( ! $user ) {
			$users = get_users( array( 'role' => 'administrator', 'number' => 1 ) );
			if ( isset( $users[0] ) && is_a( $users[0], 'WP_User' ) ) {
				$user = $users[0];
			}
		}

		return $user;
	}

}

if ( ! function_exists( 'eig_sso_login_user' ) ) {

	/**
	 * Log a user into WordPress.
	 *
	 * @param WP_User $user
	 */
	function eig_sso_login_user( WP_User $user ) {
		wp_set_current_user( $user->ID, $user->user_login );
		wp_set_auth_cookie( $user->ID );
		do_action( 'wp_login', $user->user_login, $user );
	}

}