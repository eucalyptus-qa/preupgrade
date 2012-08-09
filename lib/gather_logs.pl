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

### read the input list
read_input_file();

if( $source_lst[0] eq "PACKAGE" || $source_lst[0] eq "REPO" ){
        $ENV{'EUCALYPTUS'} = "";
};

### Prepare Log Directory
my $log_dir = "../artifacts/logs/";

if( -e "$log_dir" ){
	system("rm -fr $log_dir");
};
system("mkdir -p $log_dir");



my $is_error = 0;

for( my $i = 0; $i < @ip_lst; $i++){

	print "\n";
	print "------------------------------ ";
	print $ip_lst[$i] . " [ ". $roll_lst[$i] ." ] ------------------------------\n";
	
	if( $roll_lst[$i] =~ /CLC/ ){
		get_clc_log($ip_lst[$i]);
	}elsif( $roll_lst[$i] =~ /SC(\d+)/ ){
		get_sc_log($ip_lst[$i], $1);
	}elsif( $roll_lst[$i] =~ /WS/ ){
		get_ws_log($ip_lst[$i]);
	};

	if( $roll_lst[$i] =~ /CC(\d+)/ ){
		my $temp_index = $1;
		get_cc_log($ip_lst[$i], $temp_index);
		if( !($roll_lst[$i] =~ /CLC/) ){
			get_cc_log_extra($ip_lst[$i], $temp_index);
		};
	};

	if( $roll_lst[$i] =~ /NC(\d+)/ ){
		get_nc_log($ip_lst[$i], $1);
	};

	print "\n";

};


print "\n";
print "-----------------------------------------------------------------------------\n";

if( $is_error == 1 ){
	print "[TEST_REPORT]\tFAILED to Download Some of the Log Files !!\n\n";
	exit(1);
};

print "[TEST_REPORT]\tSuccessfully Downloaded All of the Log Files\n\n";

exit(0);

1;



############# subroutine ####################



sub get_clc_log{

	my $this_ip = shift @_;

	#Grabbing Cloud Log
	system( "mkdir -p $log_dir" . $this_ip . "_CLC" );

	print "\nDownload Logs from CLC\n";
	print "\n";

	print "Machine $this_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-*.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-* " . $log_dir . $this_ip . "_CLC/" , 60);
	check_timed_run("cloud-output.log from $this_ip");


	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/db*\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/db* " . $log_dir . $this_ip . "_CLC/" , 60);

        my $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No db* files\n";
                print "\n";
        };

	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/startup.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/startup.log " . $log_dir . $this_ip . "_CLC/" , 60);

        $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No startup.log file\n";
                print "\n";
        };

	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/euca_imager.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/euca_imager.log " . $log_dir . $this_ip . "_CLC/" , 60);

        $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No euca_imager.log file\n";
                print "\n";
        };


	get_hprof_file($this_ip, $log_dir . $this_ip . "_CLC/");

	get_sys_log_files($this_ip, $log_dir . $this_ip . "_CLC/");

	return 0;
};


sub get_cc_log{

	my $this_ip = shift @_;
	my $this_group = shift @_;
	
	my $group = sprintf("%02d", $this_group);

	my $my_cc_ip = $this_ip;

	#Grabbing CC Log
	system( "mkdir -p $log_dir" . $my_cc_ip . "_CC" . $group );

	print "\nDownload Logs from CC$group\n";
	print "\n";

	print "Machine $my_cc_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc.log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_cc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/cc* " . $log_dir . $my_cc_ip . "_CC" . $group . "/", 60);
	check_timed_run("cc.log from $cc_ip");

	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/httpd-cc_error_log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_cc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/httpd-cc_error_log* " . $log_dir . $my_cc_ip . "_CC" . $group . "/", 60);
	check_timed_run("httpd-cc_error_log from $cc_ip");

	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/axis2c.log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_cc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/axis2c.log " . $log_dir . $my_cc_ip . "_CC" . $group . "/", 60);
	check_timed_run("axis2c.log from $cc_ip");

	get_sys_log_files($this_ip, $log_dir . $this_ip . "_CC" . $group );

	return 0;

};


sub get_cc_log_extra{

	my $this_ip = shift @_;
        my $this_group = shift @_;

        my $group = sprintf("%02d", $this_group);

        my $my_cc_ip = $this_ip;

        #Grabbing CC Log
        system( "mkdir -p $log_dir" . $my_cc_ip . "_CC" . $group );


	print "\nDownload Extra Logs from CC$group\n";
	print "\n";

	print "Machine $this_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-*\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-* " . $log_dir . $this_ip . "_CC" . $group . "/", 60);

	my $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No cloud-* files\n";
                print "\n";
        };

	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/euca_imager.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/euca_imager.log " . $log_dir . $this_ip . "_CC" . $group . "/" , 60);

	$rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No euca_imager.log file\n";
                print "\n";
        };

	return 0;
};




sub get_nc_log{

	my $this_ip = shift @_;
	my $this_group = shift @_;

	my $group = sprintf("%02d", $this_group);

	my $my_nc_ip = $this_ip;
	
	#Copying Node Log
	system( "mkdir -p $log_dir" . $my_nc_ip . "_NC" . $group );

	print "\nDownload Logs from NC$group\n";
	print "\n";

	print "Machine $my_nc_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/nc.log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_nc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/nc* " . $log_dir . $my_nc_ip . "_NC" . $group  . "/", 60);
	check_timed_run("nc.log from $my_nc_ip");

	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/httpd-nc_error_log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_nc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/httpd-nc_error_log* " . $log_dir . $my_nc_ip . "_NC" . $group  . "/", 60);
	check_timed_run("httpd-nc_error_log from $my_nc_ip");

	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/axis2c.log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_nc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/axis2c.log " . $log_dir . $my_nc_ip . "_NC" . $group  . "/", 60);
	check_timed_run("axis2c.log from $my_nc_ip");

	get_sys_log_files($this_ip, $log_dir . $this_ip . "_NC" . $group );

	return 0;
};



sub get_sc_log{

	my $this_ip = shift @_;
	my $this_group = shift @_;

	my $group = sprintf("%02d", $this_group);

	my $my_sc_ip = $this_ip;
	
	#Copying SC Log
	system( "mkdir -p $log_dir" . $my_sc_ip . "_SC" . $group );

	print "\nDownload Logs from SC$group\n";
	print "\n";

	print "Machine $my_sc_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-*.log\n";
	
	timed_run("scp -o StrictHostKeyChecking=no root\@$my_sc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-* " . $log_dir . $my_sc_ip . "_SC" . $group  . "/", 60);
	check_timed_run("sc.log from $my_sc_ip");

	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/sc-stats.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$my_sc_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/sc-stats.log " . $log_dir . $my_sc_ip . "_SC" . $group  . "/", 60);

        my $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No sc-stats.log file\n";
                print "\n";
        };

	get_hprof_file($this_ip, $log_dir . $this_ip . "_SC" . $group );

	get_sys_log_files($this_ip, $log_dir . $this_ip . "_SC" . $group );

	return 0;
};


sub get_ws_log{

	my $this_ip = shift @_;

	#Grabbing WALRUS Log
	system( "mkdir -p $log_dir" . $this_ip . "_WS" );

	print "\nDownload Logs from WALRUS\n";
	print "\n";

	print "Machine $this_ip\n\n";
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-*.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/cloud-* " . $log_dir . $this_ip . "_WS/" , 60);
	check_timed_run("cloud-output.log from $this_ip");


	###	ADDED 122911
	print "Retrieving Files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/walrus-stats.log\n";

	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/walrus-stats.log " . $log_dir . $this_ip . "_WS/" , 60);

        my $rc = $? >> 8;

        if( $rc == 1 ){
                print "\n";
                print "No walrus-stats.log file\n";
                print "\n";
        };


	get_hprof_file($this_ip, $log_dir . $this_ip . "_WS/");
	get_sys_log_files($this_ip, $log_dir . $this_ip . "_WS/");

	return 0;
};

sub get_hprof_file{
	my $this_ip = shift @_;
	my $location = shift @_;

	print "\n";
	print "Machine $this_ip\n\n";
	print "Trying to Retrieve *.hprof files $ENV{'EUCALYPTUS'}/var/log/eucalyptus/*.hprof\n";

        timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:$ENV{'EUCALYPTUS'}/var/log/eucalyptus/*.hprof $location" , 120);

	my $rc = $? >> 8;

	if( $rc == 0 ){
		print "\n";
		print "*** Found *.hprof files ***\n";
		print "\n";
	}else{
		print "\n";
		print "No *.hprof files\n";
		print "\n";
	};

	return 0;
};


sub get_sys_log_files{
	my $this_ip = shift @_;
	my $location = shift @_;

	print "\n";
	print "Machine $this_ip\n\n";

	print "Trying to Retrieve Sys Log Files /var/log/messages*\n";
        timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:/var/log/messages* $location" , 120);
	print "\n";

	print "Trying to Retrieve Sys Log Files /var/log/debug*\n";
        timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:/var/log/debug* $location" , 120);
	print "\n";

	print "Trying to Retrieve Sys Log Files /var/log/kern*\n";
        timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:/var/log/kern* $location" , 120);
	print "\n";

	print "Trying to Retrieve Sys Log Files /var/log/daemon*\n";
	timed_run("scp -o StrictHostKeyChecking=no root\@$this_ip:/var/log/daemon* $location" , 120);
	print "\n";

	return 0;
};


sub check_timed_run{
	my $str = shift;

	my $rc = $? >> 8;

	if( $rc == 1 ){
		print "\n[TEST_REPORT]\tFAILED to Download the Log File $str !!\n";
		print "\n";
		$is_error = 1;
		return 1;
	};

	print "\n";	
	print "OK\n";
	print "\n";
	return 0;
};




sub read_input_file{
	
	my $index = 0;

	open( LIST, "< ../input/2b_tested.lst" ) or die $!;

	my $line;
	while( $line = <LIST> ){
		chomp($line);
		if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
	                print "IP $1 [Distro $2, Version $3, Arch $4] will be built from $5 with Eucalyptus-$6\n";
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

return 0;

};


1;


# <START_DESCRIPTION>
# NAME: _gather_logs
# LANGUAGE: perl
# USAGE: _gather_logs  
# REQUIREMENT : 2b_tested.lst file in your ./input directory of this test directory
#               set up passwordless ssh connection to all the machines in 2b_tested.lst; this can be accomplished by running _copy_rsa_keys script
# DESCRIPTION : This script gathers all the log files from the machines in 2b_test.lst file
# <END_DESCRIPTION>


