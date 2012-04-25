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

			my $this_roll = $6;

			if( does_It_Have($this_roll, "CLC") ){
				$clc_index = $index;
				$clc_ip = $1;
			};

			if( does_It_Have($this_roll, "CC") ){
				$cc_index = $index;
				$cc_ip = $1;

				if( $this_roll =~ /CC(\d+)/ ){
					$cc_lst{"CC_$1"} = $cc_ip;
					if( $1 > $max_cc_num ){
						$max_cc_num = $1;
					};
				};			
			};

			if( does_It_Have($this_roll, "SC") ){
				$sc_index = $index;
				$sc_ip = $1;

				if( $this_roll =~ /SC(\d+)/ ){
                	                $sc_lst{"SC_$1"} = $sc_ip;
                	        };
			};

			if( does_It_Have($this_roll, "WS") ){
                	        $ws_index = $index;
                	        $ws_ip = $1;
                	};

			if( does_It_Have($this_roll, "NC") ){
				$nc_ip = $1;
				if( $this_roll =~ /NC(\d+)/ ){
					if( $nc_lst{"NC_$1"} eq	 "" ){
                	                	$nc_lst{"NC_$1"} = $nc_ip;
					}else{
						$nc_lst{"NC_$1"} = $nc_lst{"NC_$1"} . " " . $nc_ip;
					};
                	        };
                	};

			$index++;
		};
        };
};

close( LIST );


if( $source_lst[0] eq "PACKAGE" || $source_lst[0] eq "REPO" ){
	$ENV{'EUCALYPTUS'} = "";
};


my $euca_version = "1.6";

if( $ENV{'EUCA_VERSION'} ne "") {
	$euca_version = $ENV{'EUCA_VERSION'};
};


for( my $i = 0; $i <= $max_cc_num; $i++){

	my $group = sprintf("%02d", $i);

	my $my_cc_ip = $cc_lst{"CC_$group"};

	#Checking Cloud Log
	#print "\n$clc_ip :: tail -n 200 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-output.log | grep $my_cc_ip\n";
	#timed_run("ssh -o StrictHostKeyChecking=no root\@$clc_ip \"tail -n 200 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-output.log | grep $my_cc_ip \" ", 10);

	print "\n$clc_ip :: tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-output.log\n";
        timed_run("ssh -o StrictHostKeyChecking=no root\@$clc_ip \"tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-output.log \" ", 10);	

	check_timed_run("cloud-output.log from $clc_ip");
	
	my @nc_ips = split( / /, $nc_lst{"NC_$group"} );
	
	foreach my $my_nc_ip ( @nc_ips ){
		#Checking Cluster Log
		#print "\n$my_cc_ip :: tail -n 500 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc.log | grep $my_nc_ip\n";
		#timed_run("ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"tail -n 500 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc.log | grep $my_nc_ip\" ", 10);
		print "\n$my_cc_ip :: tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc.log\n";
                timed_run("ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc.log\" ", 10);
		check_timed_run("cc.log from $cc_ip");

		#Checking Node Log
                print "\n$my_nc_ip :: tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/nc.log \n";
                timed_run("ssh -o StrictHostKeyChecking=no root\@$my_nc_ip \"tail -n 5 $ENV{'EUCALYPTUS'}/var/log/eucalyptus/nc.log\" ", 10);
		check_timed_run("nc.log from $my_nc_ip");
	};
};



############# subroutine ####################

sub check_timed_run{
	my $origin = shift;

        if( was_outstr() ){
		print "$origin returned output\n";
		print "COMMAND => " . get_recent_cmd() . "\n";
                print "STDOUT => " . get_recent_outstr() . "\n";

		if( $origin =~ /cloud/ && $ENV{'EUCA_VERSION'} eq "1.5" ){
			#skip...ver 1.5's cloud-output.log does not contain timestamp
		}else{
			check_timestamp($origin);
		};

        }elsif( was_errstr() ){
#                open( ERR_REPORT, ">> ../artifacts/polling_ok.err" ) or die $!;
#                print ERR_REPORT "$origin returned errors.\n";
#                print ERR_REPORT get_recent_errstr() . "\n";
		print "ERROR => $origin returned errors.\n";
		print "ERROR => " . get_recent_errstr() . "\n";
#                close( ERR_REPORT );
                exit(0);
        }else{
#                open( ERR_REPORT, ">> ../artifacts/polling_ok.err" ) or die $!;
#                print ERR_REPORT "$origin returned no result.\n";
		print "ERROR => $origin returned no result.\n";
#                close( ERR_REPORT );
                exit(0);
        };
};

sub check_timestamp{
	my $origin = shift;
	
	my @lines = split( /\n/, get_recent_outstr() );
	my $count = @lines;
	my $last_hr = 0;
	my $last_min = 0;
	if ( $lines[$count-1] =~ /(\d\d):(\d\d):(\d\d)/ ){
		$last_hr = $1;
		$last_min = $2;
	}else{
		print "ERROR => $origin output has no timestamp in last message\n";

		return 0;		## for now, let's not consider this as an ERROR
	};

	my ($sec,$min,$hour,$mday,$mon,$year,$wday, $yday,$isdst)=localtime(time);
        my $curr_hr = sprintf "%02d", $hour;
	my $curr_min = sprintf "%02d", $min;

	my $ts = print_time();

	if( $last_hr == $curr_hr ){
		if( $curr_min > $last_min + 10 ){
			print "$ts\t[TEST_REPORT]\tWARNING => $origin displays delay longer than 10 mins\n";
                	exit(0);
		};
	}elsif( $last_hr + 1 == $curr_hr || ( $last_hr == 23 && $curr_hr == 0 ) ){
		if( $curr_min + 60 > $last_min + 10 ){
			print "$ts\t[TEST_REPORT]\tWARNING => $origin displays delay longer than 10 mins\n";
                        exit(0);
		};
	}elsif( $last_hr == $curr_hr +1 || ( $curr_hr == 23 && $last_hr == 0 ) ){ 
		if( $last_min + 60 > $curr_min + 10 ){
			print "$ts\t[TEST_REPORT]\tWARNING => $origin displays delay longer than 10 mins\n";
                        exit(0);
		};
	}else{
		print "$ts\t[TEST_REPORT]\tWARNING => $origin displays delay longer than an hour\n";
                exit(0);
	};

	return 0;
};

sub print_time{
        my ($sec,$min,$hour,$mday,$mon,$year,$wday, $yday,$isdst)=localtime(time);
        my $this_time = sprintf "[%4d-%02d-%02d %02d:%02d:%02d]", $year+1900,$mon+1,$mday,$hour,$min,$sec;
        return $this_time;
};



1;




# <START_DESCRIPTION>
# NAME: _polling_ok
# LANGUAGE: perl
# USAGE: _polling_ok
# REQUIREMENT : 2b_tested.lst file in your ./input directory of this test directory
#               set up passwordless ssh connection to all the machines in 2b_tested.lst; this can be accomplished by running _copy_rsa_keys script
# DESCRIPTION : This script checks if CLC node is polling from CC node(s) and CC node is polling from NC node(s) 
# <END_DESCRIPTION>

