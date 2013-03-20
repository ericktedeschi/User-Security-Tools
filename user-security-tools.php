<?php
/*
Plugin Name: User Security Tools
Plugin URI: http://oerick.com/user-security-tools
Description: Security Tools for user management: stop brute force, password policy, password reset, password history.
Version: 1.1.2
Author: Erick Belluci Tedeschi
Author URI: http://oerick.com
License: GPL2
 */

/*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, 
* USA.
**/

// The plugin can't be called directly
if (!function_exists('add_action')) {
    echo "Ma oeeeee";
    exit();
}

class UserSecurityTools
{
    // stores status for error functions 
    private $passwordErrors = array();

    private $settings = array();

    const PASSWORD_STRENGTH_LOW = 1;
    const PASSWORD_STRENGTH_MEDIUM = 2;
    const PASSWORD_STRENGTH_HIGH = 3;

    public function __construct()
    {
        // Plugin Activation/Deactivation hooks
        register_activation_hook(__FILE__, array(&$this, 'pluginActivation'));
        register_deactivation_hook(__FILE__, array(&$this, 'pluginDeactivation'));

        // plugin init
        add_action('init', array(&$this, 'init'));

        // Add Network Admin Menu to manage users of all blogs
        if (is_multisite() && is_network_admin()) {
            add_action('network_admin_menu', array(&$this, 'adminMenu'), 10, 0);
        } else {
            add_action('admin_menu', array(&$this, 'adminMenu'), 10, 0);
        }

        // Custom fields in settings
        add_filter('wpmu_options', array(&$this, 'wpmuOptions'));
        add_filter('update_wpmu_options', array(&$this, 'updateWpmuOptions'));


        // Authentication related hooks
        add_filter('wp_authenticate_user', array(&$this, 'wpAuthenticateUser'), 10, 2);
        add_action('wp_login_failed', array(&$this, 'wpLoginFailed'));
        add_action('wp_login', array(&$this, 'wpLogin'));

        // Ensure that the password is acoording to policy
        add_action('check_passwords', array(&$this, 'checkPasswords'), 10, 3);
        add_action('user_profile_update_errors', array(&$this, 'checkPasswordsErrors'), 100, 3);

        // Hooks for add/del metas when add/delete user
        add_action('wpmu_new_user', array(&$this, 'addUserDefaultMeta'));
        add_action('user_register', array(&$this, 'addUserDefaultMeta'));
        add_action('wpmu_delete_user', array(&$this, 'delUserDefaultMeta'));

        add_action('password_reset', array(&$this, 'passwordReset'), 10, 2);
    }

    public function init() {
        if (is_multisite()) {
            $settings = get_site_option('ust_settings', array());
        } else {
            $settings = get_site_option('ust_settings', array());
        }
        if (count($settings) === 0) {
            add_action('network_admin_notices', array(&$this, 'networkAdminNotice'));
        }

        $this->settings = array_merge($this->settings, $settings);
        if (is_multisite()) {
            $this->settings['sust_max_login_attempts'] = get_site_option('sust_max_login_attempts', 5);
            $this->settings['sust_login_grace_time'] = get_site_option('sust_login_grace_time', 3); 
        } else {
            $this->settings['sust_max_login_attempts'] = get_option('sust_max_login_attempts', 5);
            $this->settings['sust_login_grace_time'] = get_option('sust_login_grace_time', 3); 
        }
    }

    public function networkAdminNotice() {
        echo "<div id='ust_notice' class='error'>User Security Tools: Plugin settings is not acessible, try to deactivate and activate again.</div>\r\n";
    }

    /**
     * checks if the password is according to the policy
     *
     * @param array $credential array with user credential array('user_login', 
     * 'password1', 'passowrd2');
     */
    public function checkPasswords($username, $password1, $password2) {

        // From form: If you would like to change the password type a new one. Otherwise leave this blank.
        if (($password1 == '') && ($password2 == '')) {
            return;
        }

        if (strlen($password1) < $this->settings['password_minchars']) {
            $this->passwordErrors[] = '<strong>The password must be at least ' . $this->settings['password_minchars'] . ' characters</strong>';
        }
        if (strlen($password1) > $this->settings['password_maxchars']) {
            $this->passwordErrors[] = '<strong>The password can be up to ' . $this->settings['password_maxchars'] . ' characters</strong>';
        } 

        switch ($this->settings['password_strength']) {
            case self::PASSWORD_STRENGTH_LOW:
                if (!preg_match('/[0-9]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one digit 0..9</strong>';
                }
                break;
            case self::PASSWORD_STRENGTH_MEDIUM:
                if (!preg_match('/[0-9]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one digit 0..9</strong>';
                }
                if (!preg_match('/[a-z]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one lower case letter</strong>';
                }
                if (!preg_match('/[A-Z]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one upper case letter</strong>';
                }

                break;
            case self::PASSWORD_STRENGTH_HIGH:
            default:
                if (!preg_match('/[0-9]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one digit 0..9</strong>';
                }
                if (!preg_match('/[a-z]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one lower case letter</strong>';
                }
                if (!preg_match('/[A-Z]+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one upper case letter</strong>';
                }
                if (!preg_match('/\W+/', $password1)) {
                    $this->passwordErrors[] = '<strong>The password must have at least one symbol: !@#$%&*()[]{}</strong>';
                }
                break;
        }
        $user = get_user_by('login', $username);
        if ($user === false) {
            //skip for new users
            return;
        }
        $userLastPasswords = get_user_meta($user->ID, 'sust_lastpasswords', true);
        foreach ($userLastPasswords as $lastPassword) {
            if (wp_check_password($password1, $lastPassword['hash'])) {
                $this->passwordErrors[] = '<strong>The password cannot be equals the last 5</strong>';
                break;
            }
        }
        return;
    }

    public function checkPasswordsErrors (&$errors, $update, &$user)
    {
        // Skip if the user isn't changing the password
        if ( (isset($_POST['pass1']) && isset($_POST['pass2'])) && ($_POST['pass1'] == '' && $_POST['pass2'] == '') ) {
            return;
        }

        if (count($this->passwordErrors) > 0) {
            foreach ($this->passwordErrors as $error) {
                $errors->add('pass', $error);
            }
        }
        if (count($errors->errors) === 0) {
            // se nao houver alteracao de senha arrumar a poha
            $this->addPasswordHistory($user->ID, $user->user_pass);
        }
    }

    public function wpmuOptions() {
?>
<hr />
<h3>User Security Tools - Settings</h3>
<table id="sust_options" class="form-table">
    <tr valign="top">
        <th scope="row">Password Strength</th>
        <td>
           <label><input type="radio" name="ust_password_strength" value="1" <?php echo ($this->settings['password_strength'] == self::PASSWORD_STRENGTH_LOW) ? "checked=\"checked\" " : "" ?> /> Low - only upper or lower case plus numeric digit</label><br />
           <label><input type="radio" name="ust_password_strength" value="2" <?php echo ($this->settings['password_strength'] == self::PASSWORD_STRENGTH_MEDIUM) ? "checked=\"checked\" " : "" ?> /> Medium - For each set, there should be at least one match in the user password (a-z, A-Z, 0-9)</label><br />
           <label><input type="radio" name="ust_password_strength" value="3" <?php echo ($this->settings['password_strength'] == self::PASSWORD_STRENGTH_HIGH) ? "checked=\"checked\" " : "" ?> /> High - For each set, there should be at least one match in the user password (a-z, A-Z, 0-9, !@#$%&*()[]{})</label><br />
        </td>
    </tr>
    <tr valign="top">
        <th scope="row">Min password characters</th>
        <td><input type="text" name="ust_password_minchars" id="ust_password_minchars" size="10" value="<?php echo esc_attr($this->settings['password_minchars']); ?>" /></td>
    </tr>
    <tr valign="top">
        <th scope="row">Max password characters</th>
        <td><input type="text" name="ust_password_maxchars" id="ust_password_maxchars" size="10" value="<?php echo esc_attr($this->settings['password_maxchars']); ?>" /></td>
    </tr>
    <tr valign="top">
        <th scope="row">Max Login Attempts</th>
        <td><input type="text" name="sust_max_login_attempts" id="sust_max_login_attempts" size="10" value="<?php echo esc_attr($this->settings['sust_max_login_attempts']); ?>" /></td>
    </tr>
    <tr valign="top">
        <th scope="row">Login grace time</th>
        <td><input type="text" name="sust_login_grace_time" id="sust_login_grace_time" size="10" value="<?php echo esc_attr($this->settings['sust_login_grace_time']); ?>" />min</td>
    </tr>
</table>
<?php
    }

    public function updateWpmuOptions() {
        if ( !current_user_can('manage_options') ) {
            wp_die( __( 'You do not have permission to access this page.' ) );
        }
        $errors = array();
        if (isset($_POST['sust_max_login_attempts']) &&
            ($_POST['sust_max_login_attempts'] >= 0) &&
            ($_POST['sust_max_login_attempts'] <= 20) ) {
            if (is_multisite()) {
                update_site_option('sust_max_login_attempts', (int)$_POST['sust_max_login_attempts']);
            } else {
                update_option('sust_max_login_attempts', (int)$_POST['sust_max_login_attempts']);
            }
        } else {
            $errors[] = 'Max login attempts must be between 0 and 20';
        }
        if (isset($_POST['sust_login_grace_time']) &&
            ($_POST['sust_login_grace_time'] >= 0) &&
            ($_POST['sust_login_grace_time'] <= 1440) ) { // 1440 min = 24 hours
            if (is_multisite()) {
                update_site_option('sust_login_grace_time', (int)$_POST['sust_login_grace_time']);
            } else {
                update_option('sust_login_grace_time', (int)$_POST['sust_login_grace_time']);
            }
        } else {
            $errors[] = 'The minutes of Login Grace Time must be a value between 0 (minutes) and 1440 (minutes = 24hours)';
        }

        if (isset($_POST['ust_password_minchars']) &&
            ($_POST['ust_password_minchars'] >= 6) &&
            ($_POST['ust_password_minchars'] <= 100) ) { // Do you really need more than 100 chars?
            $password_minchars = (int)$_POST['ust_password_minchars'];
        } else {
            $password_minchars = $this->settings['password_minchars'];
            $errors[] = 'The value of Password Min Chars must be between 6 and 100';
        }
        if (isset($_POST['ust_password_maxchars']) &&
            ($_POST['ust_password_maxchars'] >= 6) &&
            ($_POST['ust_password_maxchars'] <= 100) ) { // Do you really need more than 100 chars?
            $password_maxchars = (int)$_POST['ust_password_maxchars'];
        } else {
            $password_maxchars = $this->settings['password_maxchars'];
            $errors[] = 'The value of Password Max Chars must be between 6 and 100';
        }

        // ensure that the maxchars is greater than minchars
        if ($password_minchars > $password_maxchars) {
            $password_maxchars = $password_minchars;
        }

        if ( isset($_POST['ust_password_strength']) && 
             ($_POST['ust_password_strength'] >= self::PASSWORD_STRENGTH_LOW) && 
             ($_POST['ust_password_strength'] <= self::PASSWORD_STRENGTH_HIGH) ) {
            $password_strength = (int)$_POST['ust_password_strength'];
        } else {
            $password_strength = $this->settings['password_strength'];
        }

        if (is_multisite()) {
            update_site_option('ust_settings', array(
                'password_minchars' => $password_minchars,
                'password_maxchars' => $password_maxchars,
                'password_strength' => $password_strength
            ));
        } else {
            update_option('ust_settings', array(
                'password_minchars' => $password_minchars,
                'password_maxchars' => $password_maxchars,
                'password_strength' => $password_strength
            ));
        }

        return $errors;
    }

    public function adminMenu() {
        if (is_multisite() && is_network_admin()) { // Multisite in network admin screen
            add_submenu_page('users.php', 'User Security Tools', 'User Security Tools', 'manage_network_users', 'user-security-tools', array(&$this, 'networkAdminPage'));
        } elseif (is_multisite()) { // Multisite in specific site admin screen
            // I think add_users is the capability that an admin needs to 
            // lock, unlock and reset users passowrd
            add_submenu_page('users.php', 'User Security Tools', 'User Security Tools', 'add_users', 'user-security-tools', array(&$this, 'networkAdminPage'));
        } else {
            add_submenu_page('users.php', 'User Security Tools', 'User Security Tools', 'add_users', 'user-security-tools', array(&$this, 'networkAdminPage'));
            add_submenu_page('options-general.php', 'User Security Tools', 'User Security Tools', 'manage_options', 'user-security-tools-settings', array($this, 'settingsPage'));
        }
    }

    public function settingsPage() {
        if ( ! current_user_can( 'manage_options' ) ) {
            wp_die( __( 'Cheatin&#8217; uh?' ) );
        }

        if (isset($_POST['_wpnonce']) && isset($_POST['submit'])) {
            $result = $this->updateWpmuOptions();
            if (count($result) > 0) {
                echo "<div class='error'>\r\n";
                echo implode("<br />\r\n", $result);
                echo "</div>\r\n";
            }
        }
        echo "<form method='post' action=''>\r\n";
        wp_nonce_field('form-settings');
        // retrieve from database new settings stored
        $this->init();
        $this->wpmuOptions();
        submit_button('Save Changes');
        echo "</form>\r\n";
    }

    public function networkAdminPage() {
        global $wpdbi, $current_site;
        if (!current_user_can('add_users')) {
            wp_die( __( 'You do not have permission to access this page.' ) );
        }

        require_once "list-ms-user-table.php"; 
        $super_admins = get_super_admins();
        $usersListTable = new User_List_Table();
        $showListTable = false;

        // All bulk actions and row actions are in this switch
        switch ($usersListTable->current_action()) {
            case 'dounlock':
                $nonce_form_unlock = (isset($_POST['_wpnonce'])) ? $_POST['_wpnonce'] : null;
                if (!wp_verify_nonce($nonce_form_unlock, 'form-unlock')) { //bulk-users
                    wp_die('Nonce verification has been failed');
                }
                if (isset($_POST['userunlock']) && is_array($_POST['userunlock'])) {
                    $userunlock = $_POST['userunlock'];
                    if (count($userunlock) <= 0) {
                        // atypical situation
                        wp_die("There are no users to unlock");
                        break;
                    }
                    echo "<div class='wrap'>\r\n";
                    echo "<div id='icon-users' class='icon32'><br /></div>\r\n";
                    echo "<h2>User Security Tools - Bulk Unlock</h2>\r\n";
                    echo "<ul>\r\n";
                    foreach ($userunlock as $user) {
                        $user = get_user_by('id', intval($user));
                        if (!$user) continue;
                        // Ensure that the user of the action is really member 
                        // of the blog that the operation is been happening
                        if (is_multisite() && !is_network_admin()) {
                            if (!is_user_member_of_blog($user->ID)) continue;
                        }
                        $this->unlockUser($user->ID);
                        echo "\t<li>User " . $user->ID . ": " . $user->user_nicename . " was unlocked</li>\r\n";
                    }
                    echo "</ul>\r\n";
                }
                echo "<a href='" . esc_attr($_SERVER['PHP_SELF'] . "?page=" . $_REQUEST['page']) . "'>Back to User Security Tools Page</a>";
                $showListTable = false;
                break; // end dounlock
            case 'unlock':
                if (isset($_GET['user_id']) && isset($_GET['_wpnonce'])) {
                    $nonce = isset($_GET['_wpnonce']) ? $_GET['_wpnonce'] : null;
                    if (!wp_verify_nonce($nonce, 'sust_listact_nonce')) {
                        wp_die('Nonce verification has been failed');
                    }
                    $user_id = intval($_GET['user_id']);
                    // checks if the user exists
                    if (get_user_by('id', $user_id)) {
                        // Ensure that the user of the action is really member 
                        // of the blog that the operation is been happening
                        if (is_multisite() && !is_network_admin()) {
                            if (!is_user_member_of_blog($user_id)) {
                                wp_die( __( 'Cheatin&#8217; uh?' ) );
                            }
                        }
                        $this->unlockUser($user_id);
                    }
                    $showListTable = true;
                }
                if (isset($_POST['user']) && is_array($_POST['user'])) {
?>
                    <div class="wrap">
                        <div id="icon-users" class="icon32"><br/></div>
                        <h2>User Security Tools - Bulk Unlock</h2>
                        <p>Do you want to unlock users below?</p>
                        <form action="<?php echo sprintf('?page=%s&action=%s',esc_attr($_REQUEST['page']),'dounlock'); ?>" method="post">
                            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
                            <?php wp_nonce_field('form-unlock'); ?>
<fieldset>
<ul>
<?php
                    foreach ($_POST['user'] as $user) {
                        $user = get_user_by('id', intval($user));
                        if (!$user) continue;
                        echo "<li><strong>" . $user->ID . "</strong>: " . $user->user_login . "<input type='hidden' name='userunlock[]' value='" . $user->ID . "' /></li>\r\n";
                    }
?>
</ul>
<?php submit_button('Confirm Unlock'); ?>
</fieldset>
                        </form>
                    </div>
<?php
                    $showListTable = false;
                }
                break; // end unlock
            case 'dolock':
                $nonce_form_lock = (isset($_POST['_wpnonce'])) ? $_POST['_wpnonce'] : null;
                if (!wp_verify_nonce($nonce_form_lock, 'form-lock')) {
                    wp_die('Nonce verification has been failed');
                }
                if (isset($_POST['userlock']) && is_array($_POST['userlock'])) {
                    $userlock = $_POST['userlock'];
                    if (count($userlock) <= 0) {
                        // atypical situation
                        wp_die("There are no users to lock");
                        break;
                    }
                    echo "<div class='wrap'>\r\n";
                    echo "<div id='icon-users' class='icon32'><br /></div>\r\n";
                    echo "<h2>User Security Tools - Bulk lock</h2>\r\n";
                    echo "<ul>\r\n";
                    foreach ($userlock as $user) {
                        $user = get_user_by('id', intval($user));
                        if (!$user) continue;
                        // Ensure that the user of the action is really member 
                        // of the blog that the operation is been happening
                        if (is_multisite() && !is_network_admin()) {
                            if (!is_user_member_of_blog($user->ID)) continue;
                        }
                        if (in_array($user->user_login, $super_admins)) {
                             echo sprintf("<li>Warning! User cannot be locked. The user %s is a network admnistrator.</li>\r\n", $user->user_login);
                        } else if ($user->ID == get_current_user()) {
                             echo sprintf("<li>Warning! Your user cannot be blocked.\r\n");
                        } else {
                            $this->lockUser($user->ID);
                            echo "\t<li>User " . $user->ID . ": " . $user->user_nicename . " was locked</li>\r\n";
                        }
                    }
                    echo "</ul>\r\n";
                }
                echo "<a href='" . esc_attr($_SERVER['PHP_SELF'] . "?page=" . $_REQUEST['page']) . "'>Back to User Security Tools Page</a>";
                $showListTable = false;
                break; // end dolock
            case 'lock':
                if (isset($_GET['user_id']) && isset($_GET['_wpnonce'])) {
                    $nonce = isset($_GET['_wpnonce']) ? $_GET['_wpnonce'] : null;
                    if (!wp_verify_nonce($nonce, 'sust_listact_nonce')) {
                        wp_die('Nonce verification has been failed');
                    }
                    $user_id = intval($_GET['user_id']);
                    $user = get_user_by('id', $user_id);
                    if ($user) {
                        // Ensure that the user of the action is really member 
                        // of the blog that the operation is been happening
                        if (is_multisite() && !is_network_admin()) {
                            if (!is_user_member_of_blog($user_id)) {
                                wp_die( __( 'Cheatin&#8217; uh?' ) );
                            }
                        }
                        if (in_array($user->user_login, $super_admins)) {
                            $footerMessage = sprintf("Warning! User cannot be locked. The user %s is a network admnistrator.\r\n", $user->user_login);
                        } else if ($user->ID == get_current_user_id()) {
                            $footerMessage = sprintf("Warning! Your user cannot be blocked.\r\n");
                        } else {
                            $this->lockUser($user_id);
                        }
                    }
                    $showListTable = true;
                }
                if (isset($_POST['user']) && is_array($_POST['user'])) {
?>
                    <div class="wrap">
                        <div id="icon-users" class="icon32"><br/></div>
                        <h2>User Security Tools - Bulk Lock</h2>
                        <p>Do you want to lock users below?</p>
                        <form action="<?php echo sprintf('?page=%s&action=%s',esc_attr($_REQUEST['page']),'dolock'); ?>" method="post">
                            <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />

                            <?php wp_nonce_field('form-lock'); ?>
<fieldset>
<ul>
<?php
                    foreach ($_POST['user'] as $user) {
                        $user = get_user_by('id', intval($user));
                        if (!$user) continue;
                        if (in_array($user->user_login, $super_admins)) {
                            echo sprintf("<li>Warning! User cannot be locked. The user %s is a network admnistrator.</li>\r\n", $user->user_login);
                        } else {
                            echo "<li><strong>" . $user->ID . "</strong>: " . $user->user_login . "<input type='hidden' name='userlock[]' value='" . $user->ID . "' /></li>\r\n";
                        }
                    }
?>
</ul>
<?php submit_button('Confirm Lock'); ?>
</fieldset>
                        </form>
                    </div>
<?php
                    $showListTable = false;
                }
                break; // end lock
            case 'resetpassword':
	        global $wpdb, $current_site;

                if (isset($_GET['user_id']) && isset($_GET['_wpnonce'])) {
                    $nonce = $_REQUEST['_wpnonce'];
                    if (!wp_verify_nonce($nonce, 'sust_listact_nonce')) {
                        wp_die('Nonce verification has been failed');
                    }
                }

                if (!isset($_GET['user_id']) || !isset($_GET['_wpnonce'])) {
                    wp_die('Invalid user id');
                }

		$user_data = get_user_by('id', (int)$_GET['user_id']);

                if ( !$user_data ) {
                    wp_die('<strong>ERROR</strong>: Invalid user ID.<br>');
                }
                // Ensure that the user of the action is really member 
                // of the blog that the operation is been happening
                if (is_multisite() && !is_network_admin()) {
                    if (!is_user_member_of_blog($user_data->ID)) {
                        wp_die( __( 'Cheatin&#8217; uh?' ) );
                    }
                }

                // redefining user_login ensures we return the right case in the email
                $user_login = $user_data->user_login;
                $user_email = $user_data->user_email;

                $key = $wpdb->get_var($wpdb->prepare("SELECT user_activation_key FROM $wpdb->users WHERE user_login = %s", $user_login));
                if ( empty($key) ) {
                    // Generate something random for a key...
                    $key = wp_generate_password(20, false);
                    // Now insert the new md5 key into the db
                    $wpdb->update($wpdb->users, array('user_activation_key' => $key, 'user_pass' => ''), array('user_login' => $user_login));
                }
                $message = "The administrator requested a password reset to the following account:\r\n\r\n";
                $message .= sprintf('Username: %s', $user_login) . "\r\n\r\n";
                $message .= network_site_url() . "\r\n\r\n";
                $message .= "If you received this email by mistake, just ignore it.\r\n\r\n";
                $message .= "To reset your password visit the following address\r\n\r\n";
                $message .= '<' . network_site_url("wp-login.php?action=rp&key=$key&login=" . rawurlencode($user_login), 'login') . ">\r\n";

                if ( is_multisite() ) {
                    $blogname = $GLOBALS['current_site']->site_name;
                } else {
                    // The blogname option is escaped with esc_html on the way into the database in sanitize_option
                    // we want to reverse this for the plain text arena of emails.
                    $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
                }
                $title = sprintf('[%s] Password Reset', $blogname );

                if ( $message && !wp_mail($user_email, $title, $message) ) {
                    wp_die('The e-mail could not be sent.<br />\nPossible reason: your host may have disabled the mail() function...');
                }
                $showListTable = true;
                $footerMessage = '<strong>The user\'s password: ' . htmlentities($user_login) . ' has been reset</strong>';
                break; // end reset_password
            default:
                $showListTable = true;
                break;
        } // end switch

        if ($showListTable) {
        $usersListTable->prepare_items();
?>
            <div class="wrap">
                <div id="icon-users" class="icon32"><br/></div>
                <h2>User Security Tools - Manage Users</h2>
                <form action="" method="get" class="search-form">
                    <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
                    <?php $usersListTable->search_box('Search Users', 'user'); ?>
                </form>
                <form id="users-filter" method="post">
                    <input type="hidden" name="page" value="<?php echo esc_attr($_REQUEST['page']); ?>" />
                    <?php $usersListTable->display() ?>
                </form>
            </div>
<?php

        } // if showListTable
        if (isset($footerMessage)) {
            echo "<div class='updated'>{$footerMessage}</div>";
        }
    }

    public function wpAuthenticateUser( $user, $password ) {
        if (is_wp_error($user)) {
            return $user;
        }
        $islocked = get_user_meta($user->ID, 'sust_locked', true);
        if ($islocked == '1') {
            return new WP_Error('sust_user_locked', '<strong>Error: This user is locked</strong>', 'user-security-tools');
        }
        return $user;
    }

    /**
     * Increment failed login attempts
     *
     * @param string $username failed login
     */
    public function wpLoginFailed( $username ) {
        $user = get_user_by('login', $username);
        if ( !$user || ($user->user_login != $username)) {
            return;
        }

        $sust_fail_attempts = (int)get_user_meta($user->ID, 'sust_fail_attempts', true);
        $sust_last_login_fail = get_user_meta($user->ID, 'sust_last_login_fail', true);
        $locked = (int)get_user_meta($user->ID, 'sust_locked', true);

        // User is already locked?
        if ($locked == 1) {
            return;
        }

        $difftime = time() - (int)$sust_last_login_fail;
        $grace_time_seconds = (int)$this->settings['sust_login_grace_time'] * 60;
        if (($sust_last_login_fail == 0) || ($difftime <= $grace_time_seconds)) {
            update_user_meta($user->ID, 'sust_fail_attempts', ++$sust_fail_attempts);
        }

        update_user_meta($user->ID, 'sust_last_login_fail', time());

        if ($sust_fail_attempts >= $this->settings['sust_max_login_attempts']) {
            $this->lockUser($user->ID, true);
        }

    }

    /**
     * Fires when an user logs in, so if he is locked, unlock it
     *
     * @param string $username Username to unlock when the user logs in
     */
    public function wpLogin( $username ){
        $user = get_user_by('login', $username);
        $this->unlockUser($user->ID);
    }

    /**
     * lock an user
     *
     * @param integer $id User id to lock
     * @param boolean $mail_alert Alert user about lock
     */
    private function lockUser($id, $mail_alert = false) {
        update_user_meta($id, 'sust_locked', 1);

        if ($mail_alert === true) {
            $user = get_user_by('id', $id);

            $message = "Your account has been blocked because there were several failed login attempts.\r\n\r\n";
            $message .= network_site_url() . "\r\n\r\n";
            $message .= sprintf('Username: %s', $user->user_login) . "\r\n\r\n";
            $message .= "Contact your administrator for more information.\r\n";

            if ( is_multisite() ) {
                $blogname = $GLOBALS['current_site']->site_name;
            } else {
                // The blogname option is escaped with esc_html on the way into the database in sanitize_option
                // we want to reverse this for the plain text arena of emails.
                $blogname = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
            }
            $subject = "{$blogname} - Account blocked";

            $headers = "bcc: " . get_option('admin_email');

            if ( $message && !wp_mail($user->user_email, $subject, $message, $headers) ) {
                wp_die('The e-mail could not be sent.<br />\nPossible reason: your host may have disabled the mail() function...');
            }
        }
    }

    /**
     * Unlock an user
     *
     * @param integer $id User id to unlock
     */
    private function unlockUser($id) {
        update_user_meta($id, 'sust_locked', 0);
        update_user_meta($id, 'sust_fail_attempts', 0);
        update_user_meta($id, 'sust_last_login_fail', 0);
    }

    /**
     * Reset password and unlock user
     *
     * @param object $user User object
     * @param string $pass Clear text password
     */
    public function passwordReset($user, $pass) {
        global $error;
        $this->checkPasswords($user->user_login, $pass, $pass);
        if (count($this->passwordErrors) > 0) {
            $error = implode('<br />', $this->passwordErrors);
            login_header( __( 'Password Reset' ), '<p class="message reset-pass">The password is not according to the password policy <a href="' . esc_url( site_url('wp-login.php?action=resetpass&key=' . urlencode($_GET['key']) . '&login=' . urlencode($_GET['login']) )) . '">Try again</a></p>' );
            login_footer();
            exit;
        }

        $this->addPasswordHistory($user->ID, $pass);
        $this->unlockUser($user->ID);
    }

    /**
     * Adds password hash to user's password history, to ensure that the user 
     * can't use an old password
     *
     * @param integer $user_id Id number of user
     * @param string $pass Clear text password
     */
    private function addPasswordHistory($user_id, $pass) {
        //TODO: number of last possible passwords from property
            $sust_lastpasswords = get_user_meta($user_id, 'sust_lastpasswords', true);
            $sust_lastpasswords[] = array(
                'date' => date('Y-m-d H:i:s', time()),
                'hash' => wp_hash_password($pass)
            );
            // Stores only the last 5 password hashes
            if (count($sust_lastpasswords) > 5) {
                array_shift($sust_lastpasswords);
            }
            update_user_meta($user_id, 'sust_lastpasswords', $sust_lastpasswords);
    }

    /**
     * Executes in plugin activation: creates default meta for users and 
     * network settings
     */
    public function pluginActivation() {
        global $wpdb;

        // If is an network installation, the plugin only can be activated from 
        // Network Admin Screen
        if (is_multisite() && !is_network_admin()) {
            die('In Network install, the plugin must be activated from Network Admin Screen');
        }

        // TODO: Adds usermeta for all users
        $users = $wpdb->get_results($wpdb->prepare("SELECT ID FROM {$wpdb->users};"), 'ARRAY_A');

        foreach ($users as $user) {
            $this->addUserDefaultMeta($user['ID']);
        }
        if (is_multisite()) {
            add_site_option('sust_max_login_attempts', 5);
            add_site_option('sust_login_grace_time', 3);
            add_site_option('ust_settings', array(
                'password_minchars' => 12,
                'password_maxchars' => 16,
                'password_strength' => self::PASSWORD_STRENGTH_MEDIUM
            ));
        } else {
            add_option('sust_max_login_attempts', 5);
            add_option('sust_login_grace_time', 3);
            add_option('ust_settings', array(
                'password_minchars' => 12,
                'password_maxchars' => 16,
                'password_strength' => self::PASSWORD_STRENGTH_MEDIUM
            ));
        }
    }

    /**
     * Add usermeta to a specific user
     *
     * @param integer $user_id User id to add usermeta
     */
    public function addUserDefaultMeta($user_id) {
        $user_id = (int)$user_id;

        // BUG BY: Jason Buscema - Include the password of the new user in 
        // history
        
        $user_data = get_user_by('id', $user_id);
        $sust_lastpasswords[] = array(
            'date' => date('Y-m-d H:i:s', time()),
            'hash' => $user_data->user_pass
        );

        add_user_meta($user_id, 'sust_lastpasswords', $sust_lastpasswords, true);
        add_user_meta($user_id, 'sust_locked', 0, true);
        add_user_meta($user_id, 'sust_last_login_fail', 0, true);
        add_user_meta($user_id, 'sust_fail_attempts', 0, true);
    }

    /**
     * Executes in plugin deactivation
     */
    public function pluginDeactivation() {
        global $wpdb;
        $users = $wpdb->get_results($wpdb->prepare("SELECT ID FROM {$wpdb->users};"), 'ARRAY_A');
        foreach ($users as $user) {
            $this->delUserDefaultMeta($user['ID']);
        }
        if (is_multisite()) {
            delete_site_option('sust_max_login_attempts');
            delete_site_option('sust_login_grace_time');
            delete_site_option('ust_settings');
        } else {
            delete_option('sust_max_login_attempts');
            delete_option('sust_login_grace_time');
            delete_option('ust_settings');
        }
    }

    /**
     * Removes usermeta from a specific user
     *
     * @param integer $user_id User id to remove usermeta
     */
    public function delUserDefaultMeta($user_id) {
        $user_id = (int)$user_id;
        delete_user_meta($user_id, 'sust_lastpasswords');
        delete_user_meta($user_id, 'sust_locked');
        delete_user_meta($user_id, 'sust_last_login_fail');
        delete_user_meta($user_id, 'sust_fail_attempts');
    }
}

$sust = new UserSecurityTools();

