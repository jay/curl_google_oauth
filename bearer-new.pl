#!/usr/bin/env perl

=begin comment
NOTES:

Request new authorization code and token info from Google.

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
use IO::Socket;

my $dirname = dirname(File::Spec->rel2abs(__FILE__));
(defined($dirname) && $dirname ne "") || die "this script's path not found";

my $shared = File::Spec->catfile($dirname, "shared.pl");
(-e $shared) || die "shared.pl path not found: $shared";

our ($verbose,$rntimeout,$cfgfile,$lockfile,$tokenfile,$tmpfile,$tmpfile2);
do "$shared" or die "perl couldn't parse shared.pl";

my $datadir;

sub help() {
  my $helptext = '
This script requests new oauth token information from Google.

The token info is written to token.json. The new bearer token is extracted
from token.json, formatted as curl command line option --oauth2-bearer and
written to a curl configuration file bearer.cfg which can be passed to curl.

It is recommended to run ./bearer-refresh.pl to refresh the token if it has
expired, before running curl:

./bearer-refresh.pl && \
curl -sS -K bearer.cfg https://www.googleapis.com/gmail/... | jq ...

Options:
  --datadir <path>
                The directory for the data files.
                The script will chdir to the directory on startup.
                Default: The current directory.
  --verbose
                Talkative to error stream (eg stderr).
                Currently this option just affects curl.
';
  $helptext =~ s/\r$//gm;
  print $helptext;
  exit;
}

GetOptions(
  "datadir=s" => \$datadir,
  "help|?" => \&help,
  "verbose" => \$verbose
) or die;

if(defined($datadir)) {
  chdir($datadir) or die "chdir(\"$datadir\") failed: $!";
}

open(my $lockfh, ">>", $lockfile) or die "failed opening $lockfile : $!";
if(!flock($lockfh, LOCK_EX | LOCK_NB)) {
  print "waiting for lock on $lockfile (is another instance running?)\n";
  while(!flock($lockfh, LOCK_EX | LOCK_NB)) {
    sleep(1);
  }
}

my $port = 7777;
my $srvaddr = "localhost:$port";
my $urlfile = "auth-url.txt";

unlink($tmpfile, $tmpfile2);

=begin comment
Launch interactive URL in user's default browser.

Windows is tricky. To launch the URL in the user's default browser it needs to
be passed to the start command, but that means the Windows command interpreter
is called first as a shell (cmd). Unfortunately when a URL with two or more
url-escaped characters % is passed as an argument they can be misinterpreted
as variables and expanded, even if the percent is itself escaped %%. The only
correct way around this I see is to write the URL to a file and then in a batch
file read it into a variable and expand that variable, which is not then
further expanded.
=end comment
=cut
sub open_browser_url(@) {
  my ($url) = @_;

  open(my $url_fh, ">", $urlfile) or die "failed opening $urlfile : $!";
  print $url_fh $url or die "failed writing to $urlfile : $!\n";
  close($url_fh) or die "failed closing $urlfile : $!\n";

  my $cmd;

  if($^O =~ /^(?:cygwin|mingw|mswin|msys)/i) { # Windows
    my $batfile = "auth-url.bat";
    # batch should always use CRLF line endings due to LF-only batch bugs
    open(my $bat_fh, ">:crlf", $batfile)
      or die "failed opening $batfile : $!";
my $batcontent = '
@echo off
setlocal disabledelayedexpansion
::
:: This script was created by bearer-new.pl to open the Google interactive
:: authorization URL in the user\'s default browser.
::
set /p URL=<"./' . $urlfile . '"' . '
start "" "%URL%"
';
    $batcontent =~ s/\r$//gm; # strip unlikely CR so it's not written as CRCRLF
    print $bat_fh $batcontent or die "failed writing to $batfile : $!\n";
    close($bat_fh) or die "failed closing $batfile : $!\n";

    if($^O =~ /^msys/i) {
      # old msys will change argument starting with single / to a path
      # https://stackoverflow.com/q/7250130
      $cmd = "cmd //c ";
    }
    else {
      $cmd = "cmd /c ";
    }
    $cmd .= "\"$batfile\"";
 }
  else {
    $cmd = "xdg-home \"$url\"";
  }

  defined(my $pid = fork) or die "failed to fork";
  if(!$pid) {
    system($cmd);
    exit;
  }
}

my $fh;

my $server = IO::Socket::INET->new(
    Listen => 1,
    LocalAddr => $srvaddr,
    Proto => 'tcp'
    )
  or die "bind to $srvaddr failed: $@";

my $cred = read_credential("credential.txt");

my $auth_url =
"https://accounts.google.com/o/oauth2/v2/auth?" .
"client_id=" . urlencode($cred->{client_id}) . "&" .
"redirect_uri=" . urlencode("http://$srvaddr") . "&" .
"scope=" . urlencode($cred->{scope}) . "&" .
"response_type=code&access_type=offline";

print "opening browser url $auth_url\n\n";
print "(if open fails then copy url from $urlfile and paste into browser)\n\n";
open_browser_url($auth_url);

print "waiting for google to send authorization code to $srvaddr\n";

my $client = $server->accept() or die "accept failed: $!";

my $data = "";
my $buffer = "";
do
{
  defined($client->recv($buffer, 1024)) or die "recv failed: $!";
  $data .= $buffer;
} while(index($data, "\r\n\r\n") == -1);

# try to send the response and shut the connection. this is not critical.
my $response =
"HTTP/1.1 200 OK\r\nContent-Length: 71\r\n\r\n" .
"Close this tab and return to the console that is running bearer-new.pl.";
$client->send($response);
$client->shutdown(SHUT_RDWR);
$data = urldecode($data);

if($data !~ /^GET .*[?&]code=([0-9]\/[0-9A-Za-z_-]+).*/) {
  print STDERR "$data\n";
  die "authorization code not found";
}

print "received authorization code\n";

my $postdata =
"code=" . urlencode($1) . "&" .
"client_id=" . urlencode($cred->{client_id}) . "&" .
"client_secret=" . urlencode($cred->{client_secret}) . "&" .
"redirect_uri=" . urlencode("http://$srvaddr") . "&" .
"grant_type=authorization_code";

writefile_array($tmpfile2, $postdata);

my $request_time = time;
my $curl_maxwait = 300;

# POST $tmpfile2 and write valid json response to $tmpfile, or die
get_token_from_google($tmpfile2, $tmpfile, $curl_maxwait);

# add absolute expire time to token info
my $cmd =
"jq --sort-keys \". + " .
"{\\\"expires_in__absolute_utc\\\": (.expires_in + $request_time)}\" " .
"\"$tmpfile\" > \"$tmpfile2\"";

`$cmd`;
!$? || die;

# write --oauth2-bearer to $tmpfile and do atomic renames:
# $tmpfile -> $cfgfile. $tmpfile2 -> $tokenfile.
finalize();
