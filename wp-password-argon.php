<?php
/**
 * Plugin Name:         WP Password Argon
 * Plugin URI:          https://github.com/Jazz-Man/wp-password-argon
 * Description:         Securely store WordPress user passwords in database with Argon2i hashing and SHA-512 HMAC using PHP's native functions.
 * Author:              Vasyl Sokolyk
 * Author URI:          https://www.linkedin.com/in/sokolyk-vasyl
 * Requires at least:   5.2
 * Requires PHP:        7.4
 * License:             MIT
 * Update URI:          https://github.com/Jazz-Man/wp-password-argon.
 */

/**
 * Get hash of given string.
 *
 * @param string $data   Plain text to hash
 * @param string $scheme Authentication scheme (auth, secure_auth, logged_in, nonce)
 *
 * @return false|string Hash of $data
 *
 * @since 2.0.3
 */
function wp_hash(string $data, string $scheme = 'auth') {
    $salt = wp_salt($scheme);

    return hash_hmac('sha512', $data, $salt);
}

if (!function_exists('app_get_hash_password_options')) {
    /**
     * @return mixed
     */
    function app_get_hash_password_options(): array {
        return (array) apply_filters('wp_hash_password_options', []);
    }
}

if (!function_exists('app_get_wp_phpass')) {
    /**
     * @return \PasswordHash
     */
    function app_get_wp_phpass(): PasswordHash {
        global $wp_hasher;

        if (!$wp_hasher instanceof PasswordHash) {
            require_once ABSPATH.WPINC.'/class-phpass.php';
            $wp_hasher = new PasswordHash(8, true);
        }

        return $wp_hasher;
    }
}

/**
 * Determine if the plaintext password matches the encrypted password hash.
 *
 * If the password hash is not encrypted using the PASSWORD_ARGON2I algorithm,
 * the password will be rehashed and updated once verified.
 *
 * @see https://www.php.net/manual/en/function.password-verify.php
 * @see https://www.php.net/manual/en/function.password-needs-rehash.php
 *
 * @param string     $password the password in plaintext
 * @param string     $hash     the hashed password to check against
 * @param int|string $user_id  the optional user ID
 *
 * @SuppressWarnings(PHPMD.CamelCaseVariableName) $wp_hasher
 */
function wp_check_password(string $password, string $hash, $user_id = ''): bool {
    if (!password_needs_rehash($hash, PASSWORD_ARGON2I, (array) app_get_hash_password_options())) {
        $_password = wp_hash($password);

        if (empty($_password)) {
            return false;
        }

        return (bool) apply_filters(
            'check_password',
            password_verify($_password, $hash),
            $password,
            $hash,
            $user_id
        );
    }

    $_password = wp_hash($password);

    if (empty($_password)) {
        return false;
    }

    $wp_phpass = app_get_wp_phpass();

    if (!empty($user_id) && $wp_phpass->CheckPassword($password, $hash)) {
        /** @var string $hash */
        $hash = wp_set_password($password, $user_id);
    }

    return (bool) apply_filters(
        'check_password',
        password_verify($_password, $hash),
        $password,
        $hash,
        $user_id
    );
}

/**
 * Hash the provided password using the PASSWORD_ARGON2I algorithm.
 *
 * @see https://www.php.net/manual/en/function.password-hash.php
 *
 * @param string $password the password in plain text
 *
 * @return false|string
 */
function wp_hash_password(string $password) {
    $hash = wp_hash($password);

    if (empty($hash)) {
        return false;
    }

    return password_hash(
        $hash,
        PASSWORD_ARGON2I,
        (array) app_get_hash_password_options()
    );
}

/**
 * Hash and update the user's password.
 *
 * @param string     $password the new user password in plaintext
 * @param int|string $user_id  the user ID
 *
 * @return false|string|void
 */
function wp_set_password(string $password, $user_id) {
    global $wpdb;

    $hash = wp_hash_password($password);

    /** @var bool $is_api_request */
    $is_api_request = apply_filters(
        'application_password_is_api_request',
        (defined('XMLRPC_REQUEST') && XMLRPC_REQUEST)
        || (defined('REST_REQUEST') && REST_REQUEST)
    );

    if (!$is_api_request) {
        $wpdb->update($wpdb->users, [
            'user_pass' => $hash,
            'user_activation_key' => '',
        ], ['ID' => $user_id]);

        clean_user_cache((int) $user_id);

        return $hash;
    }

    if (!class_exists('WP_Application_Passwords') || empty($passwords = WP_Application_Passwords::get_user_application_passwords((int) $user_id))) {
        return;
    }

    $wp_phpass = app_get_wp_phpass();

    foreach ($passwords as $key => $value) {
        if (!$wp_phpass->CheckPassword($password, $value['password'])) {
            continue;
        }

        $passwords[$key]['password'] = $hash;
    }

    update_user_meta(
        (int) $user_id,
        WP_Application_Passwords::USERMETA_KEY_APPLICATION_PASSWORDS,
        $passwords
    );

    return $hash;
}
