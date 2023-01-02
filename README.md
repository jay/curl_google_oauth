The scripts in this project request and refresh a Google OAuth bearer token
(OAuth 2.0 access_token) that can be used for Google REST API requests made
with the [curl tool](https://curl.se/) and other tools that support bearer
tokens.

Quick Start
-----------

~~~
cat > credential.txt << EOF
client_id = REMOVED.apps.googleusercontent.com
client_secret = REMOVED
scope = https://mail.google.com/
EOF

$ ./bearer-new.pl
opening browser url https://accounts.google.com/o/oauth2/v2/auth?client_id=REMOVED.apps.googleusercontent.com&redirect_uri=http%3A%2F%2Flocalhost%3A7777&scope=https%3A%2F%2Fmail.google.com%2F&response_type=code&access_type=offline

(if open fails then copy url from auth-url.txt and paste into browser)

waiting for google to send authorization code to localhost:7777
received authorization code
requesting token data
received token data
updating bearer.cfg and token.json
token data written to bearer.cfg and token.json

$ ./bearer-refresh.pl && curl -sS -K bearer.cfg https://www.googleapis.com/gmail/v1/users/me/labels/INBOX | jq .messagesUnread
2
~~~

# Scripts

## bearer-new.pl

bearer-new.pl is a blocking script used to make the initial request for
authorization and token info from Google. The user's web browser is launched
for Google's required interactive confirmation. Once confirmed an
authorization code generated by Google is sent from the browser to the script
by loopback (locahost:7777). The script then uses that code to request new
token info from Google.

Google does not allow mobile applications (iOS, Android and Chrome App client
types) to use the authorization flow in this script. This script was written
and tested for desktop applications ("Desktop App" in cloud).

## bearer-refresh.pl

bearer-refresh.pl is a non-interactive script used to refresh token info. Since
Google's bearer token is ephemeral it will have to be refreshed before use if
it's expired.

Example:

~~~
./bearer-refresh.pl && \
curl -sS -K bearer.cfg https://www.googleapis.com/gmail/... | jq ...
~~~

The script also refreshes a bearer token that is close to expiration (default:
5 minutes) but not expired. If multiple instances of the script are running at
the same time then they wait (default: 5 minutes) for an exclusive lock. Run
`./bearer-refresh.pl --help` for options.

The token info files token.json and bearer.cfg are updated via file rename,
which is usually atomic depending on your OS and underlying file system. On
Windows a file cannot be replaced until all the programs (eg curl) close the
fopened file handles, so each rename operation is retried for up to 60 seconds.
Generally, it should be possible that multiple instances of this script and/or
curl are running at the same time.

This script will error if the refresh_token (the token used to refresh the
bearer token) has expired. Refresh tokens are not ephemeral and do not have an
expiration entry in token.json but can expire in some circumstances. Most
notably if your cloud project is in the testing phase (refer to OAuth consent
screen menu entry in cloud) Google will expire the refresh_token after 7 days.
You would have to request new token info by running bearer-new.pl again.

https://developers.google.com/identity/protocols/oauth2#expiration

## start-auth-url.bat

start-auth-url.bat is a helper script for Windows that is called by
bearer-new.pl to launch the URL for Google's interactive confirmation in the
user's default browser. There is no reason to run this script directly.

## shared.pl

shared.pl contains shared variables and functions used by bearer-new.pl and
bearer-refresh.pl. There is no reason to run this script directly.

# Data files

## auth-url.txt

auth-url.txt contains the interactive authorization URL. This file is created
by bearer-new.pl and the URL in the file should open in your browser during
authorization.

Troubleshooting: If the URL failed to open in your browser you can either copy
it from the terminal or this file and paste it into the browser, while
bearer-new.pl is running, to continue the authorization process.

## bearer.cfg

bearer.cfg contains the bearer token formatted as curl configuration option
[`--oauth2-bearer <token>`](https://curl.se/docs/manpage.html#--oauth2-bearer).
You can pass it to curl as a configuration file, eg curl -K bearer.cfg, to
use the bearer token with Google's REST API.

bearer-new.pl and bearer-refresh.pl create this file. Typically you would run
bearer-refresh.pl so that the bearer token can be updated first if necessary,
then run curl.

## credential.txt

credential.txt contains credential information from your Google cloud project.
You must create this file and use format key=value. The 3 required keys are
client_id, client_secret and scope.

Example:

~~~ini
client_id=[stuff].apps.googleusercontent.com
client_secret=[otherstuff]
scope = https://mail.google.com/
~~~

Comments are only allowed on separate lines starting with #. Leading and
trailing whitespace around key and value is ignored. Do not URL-encode the
values. If there are multiple scopes then use a space delimited set of URLs as
the value. The scopes must be from APIs that you have already enabled in your
project.

https://developers.google.com/identity/protocols/oauth2/scopes

If you haven't already you'll need to create a project in Google Cloud 'APIs &
Services > Select a project > New project', add the desired API (such as Gmail
API) in 'Enabled APIs and Services > Enable APIs and Services' and generate a
client id/secret in 'Credentials > Create  Credentials > OAuth Client ID >
Desktop App'. Also, while your project is in the testing phase, you will have
to add yourself as an authorized user via 'APIs & Services > OAuth consent
screen > Test users > Add users'.

## token.json

token.json contains the token information from Google. bearer-new.pl and
bearer-refresh.pl create this file.

Example:

~~~json
{
  "access_token": "[stuff]",
  "expires_in": 3599,
  "expires_in__absolute_utc": 1672514976,
  "refresh_token": "[otherstuff]",
  "scope": "https://mail.google.com/",
  "token_type": "Bearer"
}
~~~

- `access_token` : The bearer token. Ephemeral.

- `expires_in` : The lifetime, in seconds, of access_token.

- `expires_in__absolute_utc` : The absolute UTC expiration time of
access_token. This key is not from Google and is added by bearer-new.pl to
track the expiration time. It is calculated as expires_in + token request time.

- `refresh_token` : The token that is used to refresh access_token.

- `scope` : The approved scopes. This should be the same as the scopes you
specified in credential.txt.

- `token_type` : The type of access_token, which is always bearer. The scripts
will error if it is not set to bearer.

## token.lock

token.lock is used to handle contention of multiple running scripts. The
scripts wait for an exclusive lock on the file so that only one instance can
run at one time.

# Other

## Compatibility

Windows users should not run multiple instances of any script with different
emulators or perl interpreters at the same time since they may implement
locking differently. For example, cygwin locks differently from mswin and msys
perl.

## Dependencies

The required dependencies are
[curl](https://curl.se/download.html),
[jq](https://stedolan.github.io/jq/download/),
[perl](https://www.perl.org/get.html).

## License

This software is licensed as described in the file COPYING. It is identical to
the license used by the curl project. You may not remove my copyright or the
copyright of any contributors under the terms of the license.

## Questions

Use GitHub's project discussion to ask questions:
https://github.com/jay/curl_google_oauth/discussions

## References

- https://console.cloud.google.com/apis/dashboard
- https://console.cloud.google.com/apis/credentials
- https://developers.google.com/identity/protocols/oauth2
- https://developers.google.com/identity/protocols/oauth2/scopes
- https://developers.google.com/identity/protocols/oauth2/native-app
- https://developers.google.com/oauthplayground/

## Source

The source can be found on GitHub:
https://github.com/jay/curl_google_oauth
