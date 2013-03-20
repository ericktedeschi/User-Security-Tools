=== User Security Tools ===
Contributors: ericktedeschi
Tags: security, user, brute force, password, block, unblock, network install, password policy, password history
Requires at least: 3.3
Tested up to: 3.5.1
Stable tag: 1.1.2

Security Tools for user management: stop brute force, password policy, password reset, password history.

== Description ==

User Security Tools provides some improvements to security in wordpress.

*   Control for Brute Force: Adds a maximum of failed login attempts within a certain period of
time. If this maximum is achieved, the user is locked.
*   Password Policy: Enforces the minimun and maximum length of the password, and the level of
password that can be: low, medium and high.
*   Password History: Don't allow user to set password equals last 5 (in the next version this number
will be configurable).
*   User Management: the network admin also can lock, unlock and reset user's password manually
(in case of password reset, the user receives a new activation key and no data is lost).

== Installation ==

1. Extract the zip file and upload all files into your plugins directory, making sure to put the files in their own unique folder. 
2. Activate the plugin to the Network through the 'Plugins' menu in WordPress
3. Go to "Settings" to configure the plugin and to "Users->User Security Tools" to manage theusers.

== Screenshots ==

1. Network Admin Settings
2. User Management 

== Changelog ==

= 1.0 =
* Initial Version 

= 1.1 =
* Now both single installation mode and network installation mode are supported
* Security Fixes and Improvements

= 1.1.1 =
* BUG: The password policy is not applied when user's password is reset

= 1.1.2 =
* Show the search field on User Security Tools page
* The list of the users shows more than fixed 5 items
* BUG: When a new user is created, include the 'first' password to the history (bug reported by Jason Buscema)

