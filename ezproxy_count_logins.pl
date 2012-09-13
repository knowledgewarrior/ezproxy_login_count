#!/usr/bin/perl

use strict;
use Socket;

my $today = `date +"%Y%m%d"`;
$today =~ s/\s*$//;
$today = $ARGV[0] if ($ARGV[0]);
# set to your audit log file - YOU NEED TO TURN ON AUDIT LOGGING IN EZPROXY FIRST!  see ezproxy manual on how to do that
my $file = "/MY EZPROXY DIRECTORY/auditlogs/20110106.txt";
my $min_threshold = 3;
my %Logins = ();

&DoFile($file);

# Multiple (min_threshold) successful login locations outside local city for a user
# should be an indication of a stolen password
#
foreach my $user (keys %Logins) {
  my @IPs = split /::/, $Logins{$user};
  if ($#IPs >= $min_threshold) {
 #  print "\nAlert: Multiple login locations for $user:\n";
 my $body = $_;
     my $out = sprintf("Multiple Logins detected in EzProxy:  $user \n\n\n with the following IPs:\n\n" .  commify_series(@IPs) . "\n");

    open(MAIL, "|/usr/sbin/sendmail -t");
   
    #  email to
    my $to="my_email_address\@myhost.com";
   
   # email from   
    my $from="ezproxy";
    my $subject="EZProxy Multiple Logins detected";

    print MAIL "To: $to\n";
    print MAIL "From: $from\n";
    print MAIL "Subject: $subject\n";

# This is the gist of it all
    print MAIL $out;
                }
    close(MAIL);
 }

exit;

sub DoFile {
  my ($filename) = @_;

  open(IN, "< $file") || die;
  while(<IN>) {
    chomp;
    my ($xime,$Event,$IP,$Username,$Session,$Other) = split /\t/;
    if ($Event eq "Login.Success") {
      $Logins{$Username} = ListBuild($Logins{$Username},$IP);
    }
  }
  close IN;
}

sub ListBuild
{
   my ($list,$add) = @_;
   
   #
   # Add allowed IP addresses here
   # The one below allows all IPs from 123.456.0.0 - aka, a big subnet
   return $list if ($add =~ m/^123\.456\./);

   if ($list eq "") { return $add; }

   my @items = split /::/, $list;
   foreach my $item (@items) {
       if ($item eq $add) { return $list; }
   }
   return $list . "::" . $add;
}

sub commify_series
{
   (@_ == 0) ? ''						:
   (@_ == 1) ? $_[0]						:
   #(@_ == 2) ? join(" and ", @_)				:
   (@_ == 2) ? join("\n ", @_)				:
		#join(", ", @_[0 .. ($#_-1)], "and $_[-1]");
		join("\n ", @_[0 .. ($#_-1)], "\n $_[-1]");
}
