#!/usr/bin/perl

use strict;
use Cwd;

$ENV{'PWD'} = getcwd();

if( $ENV{'TEST_DIR'} eq "" ){
        my $cwd = getcwd();
        if( $cwd =~ /^(.+)\/lib/ ){
                $ENV{'TEST_DIR'} = $1;
        }else{
                print "ERROR !! Incorrect Current Working Directory ! \n";
                exit(1);
        };
};


open( INPUT , "../input/2b_tested.lst") or die $!;

my $line;
my @ips;

print "Test Machines\n";

while( $line = <INPUT> ){
	if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
		print "IP $1 [Distro $2, Version $3, Arch $4] was built from $5 with Eucalyptus-$6\n";
		if( !($2 eq "VMWARE" || $2 eq "WINDOWS") ){
			print $1 . "\n";
			push(@ips, $1);
		};
	};
};

close(INPUT);

print "Copying this Machine's id_rsa.pub key to the Test Machines\n";

foreach my $this_ip ( @ips ){
	print "scp -o StrictHostKeyChecking=no $ENV{'HOME'}/.ssh/id_rsa.pub root\@$this_ip:/root/.\n";
	system("scp -o StrictHostKeyChecking=no $ENV{'HOME'}/.ssh/id_rsa.pub root\@$this_ip:/root/.");
	system("ssh -o StrictHostKeyChecking=no root\@$this_ip \"cat /root/id_rsa.pub >> /root/.ssh/authorized_keys\" ");
};


print "\nThis Machine's id_rsa.pub key is SUCCESSFULLY copied to the test machines\n\n";

exit(0);

# <START_DESCRIPTION>
# NAME: _copy_rsa_key
# LANGUAGE: perl
# USAGE: _copy_rsa_key
# REQUIREMENT : id_rsa.pub file in your $HOME/.ssh directory
#               2b_tested.lst file in your ./input directory of this test directory 
# DESCRIPTION : This script copies id_rsa.pub file from this machine to all the machines described in the file 2b_tested.lst
# <END_DESCRIPTION> 


