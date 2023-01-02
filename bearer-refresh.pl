#!/usr/bin/env perl

=begin comment
NOTES:

Request updated token info from Google.

---
Copyright (C) 2023 Jay Satiro <raysatiro@yahoo.com>

This software is licensed as described in the file COPYING. The license is
identical to the license used by the curl project. You may not remove my
copyright or the copyright of any contributors under the terms of the license.

The license is also available on the internet:
https://github.com/jay/curl_google_oauth/blob/master/COPYING

=end comment
=cut

use strict;
use warnings;
use Data::Dumper;
use Fcntl qw(:flock);
use File::Basename;
use File::Spec;
use Getopt::Long;

my $path = dirname(File::Spec->rel2abs(__FILE__));
(defined($path) && $path ne "") || die "this script's path not found";
chdir($path) or die "chdir(\"$path\") failed: $!";

our ($verbose,$rntimeout,$cfgfile,$lockfile,$tokenfile,$tmpfile,$tmpfile2);
do "./shared.pl" or die "perl couldn't parse shared.pl";

my $start_time = time;
my $early = 5 * 60;
my $maxwait = 5 * 60;
my $force;

sub help() {
  my $helptext = '
This script requests Google refresh the oauth token information in token.json
if the bearer token (access_token) is close to expiration. If the bearer token
is not close to expiration then no transfer takes place, nothing is shown and
the script exits.

If the token information is refreshed then the new bearer token is extracted
from token.json, formatted as curl command line option --oauth2-bearer and
written to a curl configuration file bearer.cfg which can be passed to curl:

./bearer-refresh.pl && \
curl -sS -K bearer.cfg https://www.googleapis.com/gmail/... | jq ...

Options:
  --early <duration>
                A time period before expiration that token info is refreshed.
                0 disables early refresh.
                Optional suffix \'s\' seconds (default), \'m\' minutes.
                Default: ' . $early . ' (' . ($early/60) . ' minutes).
  --force
                Refresh the token regardless of expiration.
  --max-transfer-time <duration>
                The maximum amount of time to wait for the transfer.
                0 disables max transfer time. See remarks.
                Optional suffix \'s\' seconds (default), \'m\' minutes.
                Default: ' . $maxwait . ' (' . ($maxwait/60) . ' minutes).
  --verbose
                Talkative to error stream (eg stderr).
                Currently this option just affects curl.

The maximum transfer time affects the time spent waiting to acquire the
startup file lock (the lock is for contention of multiple instances) and the
time curl waits for a transfer to complete. If it is disabled then those
operations may block. Once the transfer is complete max transfer time does not
affect further operations. File rename is used to replace the output files
atomically and each replacement tried for up to ' . $rntimeout . ' seconds.
';
  $helptext =~ s/\r$//gm;
  print $helptext;
  exit;
}

GetOptions(
  "early=s" => \$early,
  "force" => \$force,
  "help|?" => \&help,
  "max-transfer-time=s" => \$maxwait,
  "verbose" => \$verbose
) or die;

for((\$early,\$maxwait)) {
  ($$_ =~ s/^(\d+)m$/($1*60)/e) ||
  ($$_ =~ s/^(\d+)s$/$1/) ||
  ($$_ =~ /^(\d+)$/) ||
  die "option value invalid time duration of $$_";
}

sub checkwait() { (!$maxwait || time <= $start_time + $maxwait) }

open(my $lockfh, ">>", $lockfile) or die "failed opening $lockfile : $!";
while(!flock($lockfh, LOCK_EX | LOCK_NB)) {
  checkwait or die "timeout: waiting for file lock on $lockfile";
  sleep(1);
}

my $info = read_token_info($tokenfile);

my $expire_time =
  $info->{expires_in__absolute_utc} ?
  $info->{expires_in__absolute_utc} - $early :
  time;

if(!$force && time < $expire_time) {
  exit;
}

my $cred = read_credential("credential.txt");

my $postdata =
"client_id=" . urlencode($cred->{client_id}) . "&" .
"client_secret=" . urlencode($cred->{client_secret}) . "&" .
"refresh_token=" . urlencode($info->{refresh_token}) . "&" .
"grant_type=refresh_token";

writefile_array($tmpfile2, $postdata);

my $request_time = time;
my $elapsed = $request_time - $start_time;

if($maxwait && $maxwait <= $elapsed) {
  die "timeout: exceeded max wait time of $maxwait seconds";
}

my $curl_maxwait = $maxwait ? $maxwait - $elapsed : 0;

# POST $tmpfile2 and write valid json response to $tmpfile, or die
get_token_from_google($tmpfile2, $tmpfile, $curl_maxwait);

# merge old token info + new token info + new absolute expire time
my $cmd =
"jq --sort-keys -s \".[0] + .[1] + " .
"{\\\"expires_in__absolute_utc\\\": (.[1].expires_in + $request_time)}\" " .
"\"$tokenfile\" \"$tmpfile\" > \"$tmpfile2\"";

`$cmd`;
!$? || die;

# write --oauth2-bearer to $tmpfile and do atomic renames:
# $tmpfile -> $cfgfile. $tmpfile2 -> $tokenfile.
finalize();
