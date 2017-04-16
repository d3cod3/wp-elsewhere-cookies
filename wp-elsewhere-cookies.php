<?php

/**
 * Plugin Name: WP ELSEWHERE Cookies
 * Plugin URI:  https://elsewhere.d3cod3.org
 * Description: Harden cookies encryption mechanism for wordpress.
 * Author:      n3m3da
 * Author URI:  http://d3cod3.org
 * Version:     1.0
 * Licence:     MIT
 */

/* Requires PHP 5.4 or newer */

// Deny file direct access
if (basename($_SERVER['PHP_SELF']) == basename(__FILE__)){ die('No direct access allowed. You a nasty one!'); }

// import crypto password lock key ELSEWHERE_KEY, stored outside the server document root, really useful when PHP and DB are on different hardware
require_once($_SERVER['DOCUMENT_ROOT'].'/../wp-crypto.php');

require_once(__DIR__ . "/libs/php-encryption/CryptoAutoload.php");      // php-encryption           [https://github.com/defuse/php-encryption]

use \Defuse\Crypto\Crypto;
use \Defuse\Crypto\Key;

/**
 * Decrypt a cookie, then parse it into its components
 *
 * @since 2.7.0
 *
 * @param string $cookie
 * @param string $scheme Optional. The cookie scheme to use: auth, secure_auth, or logged_in
 * @return array|false Authentication cookie components
 */
function wp_parse_auth_cookie($cookie = '', $scheme = '') {
    if ( empty($cookie) ) {
        switch ($scheme){
            case 'auth':
                $cookie_name = AUTH_COOKIE;
                break;
            case 'secure_auth':
                $cookie_name = SECURE_AUTH_COOKIE;
                break;
            case "logged_in":
                $cookie_name = LOGGED_IN_COOKIE;
                break;
            default:
                if ( is_ssl() ) {
                    $cookie_name = SECURE_AUTH_COOKIE;
                    $scheme = 'secure_auth';
                } else {
                    $cookie_name = AUTH_COOKIE;
                    $scheme = 'auth';
                }
        }

        if ( empty($_COOKIE[$cookie_name]) )
            return false;

        $ciphertext = $_COOKIE[$cookie_name];
        try {
            $decrypted = Crypto::Decrypt($ciphertext,Key::loadFromAsciiSafeString(ELSEWHERE_KEY));
        } catch (InvalidCiphertextException $ex) { // VERY IMPORTANT
            // Either:
            //   1. The ciphertext was modified by the attacker,
            //   2. The key is wrong, or
            //   3. $ciphertext is not a valid ciphertext or was corrupted.
            // Assume the worst.
            return false;
        } catch (CryptoTestFailedException $ex) {
            return false;
        } catch (CannotPerformOperationException $ex) {
            return false;
        }
        $cookie = $decrypted;
    }

    $cookie_elements = explode('|', $cookie);
    if ( count( $cookie_elements ) !== 4 ) {
        return false;
    }

    list( $username, $expiration, $token, $hmac ) = $cookie_elements;

    return compact( 'username', 'expiration', 'token', 'hmac', 'scheme' );
}

/**
 * Log in a user by setting authentication cookies.
 *
 * The $remember parameter increases the time that the cookie will be kept. The
 * default the cookie is kept without remembering is two days. When $remember is
 * set, the cookies will be kept for 14 days or two weeks.
 *
 * @since 2.5.0
 * @since 4.3.0 Added the `$token` parameter.
 *
 * @param int    $user_id  User ID
 * @param bool   $remember Whether to remember the user
 * @param mixed  $secure   Whether the admin cookies should only be sent over HTTPS.
 *                         Default is_ssl().
 * @param string $token    Optional. User's session token to use for this cookie.
 */
function wp_set_auth_cookie( $user_id, $remember = false, $secure = '', $token = '' ) {
    if ( $remember ) {
        /**
         * Filters the duration of the authentication cookie expiration period.
         *
         * @since 2.8.0
         *
         * @param int  $length   Duration of the expiration period in seconds.
         * @param int  $user_id  User ID.
         * @param bool $remember Whether to remember the user login. Default false.
         */
        $expiration = time() + apply_filters( 'auth_cookie_expiration', 14 * DAY_IN_SECONDS, $user_id, $remember );

        /*
         * Ensure the browser will continue to send the cookie after the expiration time is reached.
         * Needed for the login grace period in wp_validate_auth_cookie().
         */
        $expire = $expiration + ( 12 * HOUR_IN_SECONDS );
    } else {
        /** This filter is documented in wp-includes/pluggable.php */
        $expiration = time() + apply_filters( 'auth_cookie_expiration', 2 * DAY_IN_SECONDS, $user_id, $remember );
        $expire = 0;
    }

    if ( '' === $secure ) {
        $secure = is_ssl();
    }

    // Front-end cookie is secure when the auth cookie is secure and the site's home URL is forced HTTPS.
    $secure_logged_in_cookie = $secure && 'https' === parse_url( get_option( 'home' ), PHP_URL_SCHEME );

    /**
     * Filters whether the connection is secure.
     *
     * @since 3.1.0
     *
     * @param bool $secure  Whether the connection is secure.
     * @param int  $user_id User ID.
     */
    $secure = apply_filters( 'secure_auth_cookie', $secure, $user_id );

    /**
     * Filters whether to use a secure cookie when logged-in.
     *
     * @since 3.1.0
     *
     * @param bool $secure_logged_in_cookie Whether to use a secure cookie when logged-in.
     * @param int  $user_id                 User ID.
     * @param bool $secure                  Whether the connection is secure.
     */
    $secure_logged_in_cookie = apply_filters( 'secure_logged_in_cookie', $secure_logged_in_cookie, $user_id, $secure );

    if ( $secure ) {
        $auth_cookie_name = SECURE_AUTH_COOKIE;
        $scheme = 'secure_auth';
    } else {
        $auth_cookie_name = AUTH_COOKIE;
        $scheme = 'auth';
    }

    if ( '' === $token ) {
        $manager = WP_Session_Tokens::get_instance( $user_id );
        $token   = $manager->create( $expiration );
    }

    $auth_cookie = wp_generate_auth_cookie( $user_id, $expiration, $scheme, $token );
    $logged_in_cookie = wp_generate_auth_cookie( $user_id, $expiration, 'logged_in', $token );

    /**
     * Fires immediately before the authentication cookie is set.
     *
     * @since 2.5.0
     *
     * @param string $auth_cookie Authentication cookie.
     * @param int    $expire      The time the login grace period expires as a UNIX timestamp.
     *                            Default is 12 hours past the cookie's expiration time.
     * @param int    $expiration  The time when the authentication cookie expires as a UNIX timestamp.
     *                            Default is 14 days from now.
     * @param int    $user_id     User ID.
     * @param string $scheme      Authentication scheme. Values include 'auth', 'secure_auth', or 'logged_in'.
     */
    do_action( 'set_auth_cookie', $auth_cookie, $expire, $expiration, $user_id, $scheme );

    /**
     * Fires immediately before the logged-in authentication cookie is set.
     *
     * @since 2.6.0
     *
     * @param string $logged_in_cookie The logged-in cookie.
     * @param int    $expire           The time the login grace period expires as a UNIX timestamp.
     *                                 Default is 12 hours past the cookie's expiration time.
     * @param int    $expiration       The time when the logged-in authentication cookie expires as a UNIX timestamp.
     *                                 Default is 14 days from now.
     * @param int    $user_id          User ID.
     * @param string $scheme           Authentication scheme. Default 'logged_in'.
     */
    do_action( 'set_logged_in_cookie', $logged_in_cookie, $expire, $expiration, $user_id, 'logged_in' );

    $ciphertext_AC = Crypto::Encrypt($auth_cookie, Key::loadFromAsciiSafeString(ELSEWHERE_KEY));
    $ciphertext_LIC = Crypto::Encrypt($logged_in_cookie, Key::loadFromAsciiSafeString(ELSEWHERE_KEY));

    setcookie($auth_cookie_name, $ciphertext_AC, $expire, PLUGINS_COOKIE_PATH, COOKIE_DOMAIN, $secure, true);
    setcookie($auth_cookie_name, $ciphertext_AC, $expire, ADMIN_COOKIE_PATH, COOKIE_DOMAIN, $secure, true);
    setcookie(LOGGED_IN_COOKIE, $ciphertext_LIC, $expire, COOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true);
    if ( COOKIEPATH != SITECOOKIEPATH )
        setcookie(LOGGED_IN_COOKIE, $ciphertext_LIC, $expire, SITECOOKIEPATH, COOKIE_DOMAIN, $secure_logged_in_cookie, true);
}



?>
