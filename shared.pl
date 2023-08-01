#!/usr/bin/env perl

=begin comment
NOTES:

shared variables and functions

bearer-new.pl and bearer-refresh.pl import this script with 'do'.

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
use Time::HiRes qw(usleep);

our $verbose;
our $rntimeout = 1 * 60; # for rename_with_timeout function
our $cfgfile = "bearer.cfg";
our $lockfile = "token.lock";
our $tokenfile = "token.json";
our $tmpfile = "token.tmp";
our $tmpfile2 = "token.tmp.2";

sub sleep_ms($) { usleep($_[0] * 1000) }

sub strlen($) { defined($_[0]) ? length($_[0]) : 0; }

sub urlencode(@) {
  my ($url) = @_;
  $url =~ s/([^-_~.A-Za-z0-9])/sprintf("%%%2.2X", ord($1))/ge;
  return $url;
}

sub urldecode(@) {
  my ($url) = @_;
  $url =~ s/\+/ /g;
  $url =~ s/%([A-Fa-f\d]{2})/chr hex $1/eg;
  return $url;
}

# On Windows a file cannot be replaced until all the programs (eg curl) close
# the fopened file handles so we have to try harder to rename the file.
#
# $timeout (seconds) : If undefined or 0 then the rename is only tried once.
sub rename_with_timeout(@) {
  my ($oldname, $newname, $timeout) = @_;
  my $stop = time + (defined($timeout) ? $timeout : 0);

  (defined($oldname) && defined($newname))
    or die "rename_with_timeout missing parameter";

  while(!rename($oldname, $newname)) {
    if(time >= $stop) {
      return 0;
    }
    sleep_ms(200);
  }

  return 1;
}

# input: filename
# output: returns an array of chomped lines
sub readfile_array(@) {
  my ($filename) = @_;
  my @array;
  
  open(my $fh, "<", $filename) or die "failed opening $filename : $!";
  while(!eof($fh)) {
    defined($_ = readline $fh) or die "failed reading from $filename : $!\n";
    s/\r?\n$//;
    push @array, $_;
  }
  close($fh) or die "failed closing $filename : $!";
  
  return @array;
}

# input: filename and an array. each element written with a newline appended.
# output: none
sub writefile_array(@) {
  my ($filename, @array) = @_;

  open(my $fh, ">", $filename) or die "failed opening $filename : $!";
  for(@array) {
    print $fh "$_\n" or die "failed writing to $filename : $!";
  }
  close($fh) or die "failed closing $filename : $!";
}

# input: filename and an array of json keys
# output: returns an array of values. missing/null keys have empty values.
sub read_json(@) {
  my ($filename, @keys) = @_;

  # limit the key characters since keys are passed directly to the command line
  for(@keys) {
    (/^[A-Za-z_]+\z/)
      or die "failed due to unexpected $_ key character in input";
  }
  
  my $filter = "." . join(",.", @keys);
  my @values =
    map { s/\r?\n$//; s/^null$//; $_ }
    `jq -r "$filter" "$filename"`;
  !$? || die;
  (@keys == @values)
    or die "number of keys differs from number of values in $filename";

  return @values;
}

# input: filename and a hashref of json keys and their regex assertions
# output: returns a hashref of json keys and their values
sub read_and_verify_json(@) {
  my ($filename, $keys_regex) = @_;

  my %result;
  my @keys = sort keys %$keys_regex;
  @result{@keys} = read_json($filename, @keys);

  for(@keys) {
    if($result{$_} !~ $keys_regex->{$_}) {
      die "failed due to invalid or missing $_ value in $filename";
    }
  }

  return \%result;
}

sub read_credential(@) {
  my ($filename) = @_;

  -e $filename or die "failed reading credential: $filename doesn't exist!";

  my $vschar = '\x20-\x7E';
  my $nqchar = '\x21\x23-\x5B\x5D-\x7E';

  # These are the keys in credential and their character sets from RFC 6749.
  # https://www.rfc-editor.org/rfc/rfc6749#appendix-A
  my %keys_regex = (
    client_id =>                   qr/^[$vschar]+$/,
    client_secret =>               qr/^[$vschar]+$/,
    scope =>                       qr/^[$nqchar]+(?: [$nqchar]+)*$/
  );

  my %result;

  my @lines = readfile_array($filename);

  # credential.txt uses an ini style format foo=bar
  for(@lines) {
    my ($key, $value) = /^\s*([\w\d]+)\s*=\s*(.*?)\s*$/;
    next unless defined $value;
    $result{$key} = $value;
  }

  my @keys = sort keys %keys_regex;

  for(@keys) {
    if($result{$_} !~ $keys_regex{$_}) {
      die "failed due to invalid or missing $_ value in $filename";
    }
  }

  return \%result;
}

sub read_error_info(@) {
  my ($filename) = @_;

  -e $filename or die "failed reading error info: $filename doesn't exist!";

  my $nqchar = '\x21\x23-\x5B\x5D-\x7E';
  my $nqschar = '\x20\x21\x23-\x5B\x5D-\x7E';

  # These are the keys seen in Google's access token error response and their
  # character sets from RFC 6749.
  #
  # https://www.rfc-editor.org/rfc/rfc6749#section-5.2
  my %keys_regex = (
    error =>                       qr/^[$nqschar]+$/,
    error_description =>           qr/^[$nqschar]*$/   # empty/missing ok
  );

  return read_and_verify_json($filename, \%keys_regex);
}

sub read_token_info(@) {
  my ($filename) = @_;

  -e $filename or die "failed reading token info: $filename doesn't exist!";

  my $alpha = 'A-Za-z';
  my $digit = '0-9';
  my $vschar = '\x20-\x7E';
  my $nqchar = '\x21\x23-\x5B\x5D-\x7E';
  my $nqschar = '\x20\x21\x23-\x5B\x5D-\x7E';

  # These are the keys seen in Google's access token success response and their
  # character sets from RFC 6749.
  #
  # access_token must be a bearer token so it is checked against the more
  # restrictive character set b64token (aka token68) from RFC 6750.
  #
  # expires_in__absolute_utc is not from Google, it's added by bearer-new.pl
  # and is an absolute time based on expires_in relative time.
  #
  # https://www.rfc-editor.org/rfc/rfc6749#appendix-A
  # https://www.rfc-editor.org/rfc/rfc6750#section-2.1
  my %keys_regex = (
    access_token =>                qr/^[-._~+\/$alpha$digit]+=*$/,
    expires_in =>                  qr/^[$digit]+$/,
    expires_in__absolute_utc =>    qr/^[$digit]*$/,  # empty/missing ok
    refresh_token =>               qr/^[$vschar]+$/,
    scope =>                       qr/^[$nqchar]+(?: [$nqchar]+)*$/,
    token_type =>                  qr/^bearer$/i
  );
  
  return read_and_verify_json($filename, \%keys_regex);
}

# request token info from google
#
# success: return true. server response in outfile.
# failure: die. possible server error response in outfile.
#
# if curl times out that is a failure case.
#
# $infile  (token request post data)
# $outfile (token response json data)
# $timeout (seconds) : If undefined or 0 then curl may block.
sub get_token_from_google(@) {
  my ($infile, $outfile, $timeout) = @_;

  unlink($outfile);

  -e $infile or die "failed reading post data: $infile doesn't exist!";

  if(!defined($timeout)) {
    $timeout = 0;
  }

  $timeout =~ /^\d+\z/ or die "invalid curl timeout value of $timeout";

  print "requesting token data\n";

  # single percentage sign in the command line is ok for windows, but don't use
  # more than one for reasons described in open_browser_url comment block
  my $cmd =
  "curl -sS " . ($verbose ? "-v " : "") .
  "--data \"\@$infile\" -o \"$outfile\" " .
  "--retry 10 --retry-max-time $timeout --max-time $timeout " .
  "--write-out \"\%{response_code}\" " .
  "https://accounts.google.com/o/oauth2/token";

  my $output = `$cmd`;
  !$? || die;

  if($output !~ /^[0-9]{1,3}$/ || int($output / 100) != 2) {
    my $errinfo;
    print STDERR "http response code: $output\n";
    if($output == 400 || $output == 401) {
      eval { $errinfo = read_error_info($outfile) }
    }
    if($errinfo) {
      print STDERR "oauth error code: $errinfo->{error}\n";
      if($errinfo->{error_description} ne '') {
        print STDERR "oauth error message: $errinfo->{error_description}\n";
      }
    }
    elsif(-s $outfile) {
      print STDERR "http response body: (refer to $outfile)\n";
    }
    die "unexpected http response code != 2xx OK http";
  }

  print "received token data\n";

  return 1;
}

# almost done. at this point there must be valid token data in $tmpfile2.
sub finalize() {
  my $info = read_token_info($tmpfile2);

  writefile_array($tmpfile, "--oauth2-bearer $info->{access_token}");

  print "updating $cfgfile and $tokenfile\n";

  rename_with_timeout($tmpfile, $cfgfile, $rntimeout)
    or die "timed out: renaming $tmpfile => $cfgfile: $!";

  rename_with_timeout($tmpfile2, $tokenfile, $rntimeout)
    or die "timed out: renaming $tmpfile2 => $tokenfile: $!";

  print "token data written to $cfgfile and $tokenfile\n";
  
  return 1;
}

# return true
1;
