=== Admin Login for Cloudflare Access ===
Contributors: aarhus
Tags: login, Cloudflare Access, sso, single-sign-on, auth
Requires at least: 6.0.0
Tested up to: 6.6
Stable tag: 0.0.1
License: GPLv3
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Simple secure login through your Cloudflare Access for WordPress


== Description ==

Protect your login in to your admin dashboard using Cloudflare access and
transparently authenticate existing users.

Your site must be behind Cloudflare for this service to work, and you *must*
have  configured your access rules for using Cloudflare Zero Trust.

Once set up, the plugin will retrieve the appropriate validation keys from
Cloudflare (caching them for an hour) and then validate the CF_Authorization
cookie that is inserted by Cloudflare as it fowards the request to your
server.

