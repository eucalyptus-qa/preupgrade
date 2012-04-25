#!/usr/bin/perl

use strict;

require './timed_run.pl';

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


# does_It_Have( $arg1, $arg2 )
# does the string $arg1 have $arg2 in it ??
sub does_It_Have{
	my ($string, $target) = @_;
	if( $string =~ /$target/ ){
		return 1;
	};
	return 0;
};



#################### APP SPECIFIC PACKAGES INSTALLATION ##########################

my @ip_lst;
my @distro_lst;
my @version_lst;
my @arch_lst;
my @source_lst;
my @roll_lst;

my %cc_lst;
my %sc_lst;
my %nc_lst;

my $clc_index = -1;
my $cc_index = -1;
my $sc_index = -1;
my $ws_index = -1;

my $clc_ip = "";
my $cc_ip = "";
my $sc_ip = "";
my $ws_ip = "";

my $nc_ip = "";

my $max_cc_num = 0;

$ENV{'EUCALYPTUS'} = "/opt/eucalyptus";

#### read the input list

my $index = 0;

open( LIST, "< ../input/2b_tested.lst" ) or die $!;

my $line;
while( $line = <LIST> ){
	chomp($line);
	if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
		print "IP $1 [Distro $2, Version $3, Arch $4] was built from $5 with Eucalyptus-$6\n";
		if( !( $2 eq "VMWARE" || $2 eq "WINDOWS" ) ){
			push( @ip_lst, $1 );
			push( @distro_lst, $2 );
			push( @version_lst, $3 );
			push( @arch_lst, $4 );
			push( @source_lst, $5 );
			push( @roll_lst, $6 );
		};
        };
};

close( LIST );


my $seed_dir = "../etc/seeds/";

# copy the 2b_tested.lst file to the seed directory
system( "cp ../input/2b_tested.lst ../etc/seeds/." );

foreach my $this_ip ( @ip_lst ){
	
	print "\nCopying the files in the SEEDS directory to $this_ip\n";
	timed_run("scp -r -o StrictHostKeyChecking=no " . $seed_dir ." root\@" . $this_ip . ":/root/.", 30);
	check_timed_run("$this_ip");
	
};

print "PLANTING SEEDS HAS BEEN COMPLETED\n";

exit(0);

1;


############# subroutine ####################


sub check_timed_run{
	my $str = shift;

	my $rc = $? >> 8;

	if( $rc == 1 ){
		print "Failled to Download the Log File from $str\n";
		exit(1);
	};
	return 0;
};


# <START_DESCRIPTION>
# NAME: _plant_seed
# LANGUAGE: perl
# USAGE: _plant_seed  
# REQUIREMENT : 2b_tested.lst file in your ./input directory of this test directory
#               set up passwordless ssh connection to all the machines in 2b_tested.lst; this can be accomplished by running _copy_rsa_keys script
# DESCRIPTION : This script copies all contents in ./etc/seeds directory to /root directory of all machines listed in 2b_test.lst
# <END_DESCRIPTION>

