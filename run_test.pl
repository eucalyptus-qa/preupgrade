#!/usr/bin/perl

use strict;
use Cwd;

require './lib/timed_run.pl';

$| = 1;
#select(STDOUT); $| = 1;
#select(STDERR); $| = 1;

# always overwrites the 'PWD' to the current working directory
$ENV{'PWD'} = getcwd();
$ENV{'TEST_DIR'} = getcwd();


############## PROCESSING CONF FILE ####################################

my @lines;

if( @ARGV < 1 ){
	warn "NO CONFIG FILENAME PROVIDED !!\n";
	exit(1);
};

my $conf_file = shift @ARGV;

open( CONF, "<$conf_file") or die $!;

my $line = "";

while($line = <CONF>){
	chomp($line);
	#print $line . "\n";
	push( @lines, $line );
};

close( CONF );

my $test_name = "";

my $repeat = 1;
my $cred_included = 0;

my $exit_on_fail = "YES";
my $ignore_exit_code = "NO";

my $repeat_prerun = "NO";
my $euca_version = "1.6";

my $default_env_file = "./etc/default.env";

my $total_stages = 0;
my $env_file = "";
my $stage = -1;
my $in_stage = 0;

my $run = "NONE";
my $timeout = 0;
my $pre_cond = "";
my $post_cond = "";
my $sleeptime = 0;

my $display_option = 3; 	# 0 = no display, 1 = screen only, 2 = file only, 3 = both

my @stg;

foreach $line ( @lines ){
	chomp($line);

	if( $in_stage == 1 ){
		if( $line =~ /^\s+RUN\s(.+)/ ){
			$run = $1;
		}elsif( $line =~ /\s+TIMEOUT\s(\d+)/ ){
			$timeout = $1;
		}elsif( $line =~ /\s+_PRE_COND\s(.+)/ ){
			$pre_cond = $1;
		}elsif( $line =~ /\s+_POST_COND\s(.+)/ ){
			$post_cond = $1;
		}elsif( $line =~ /\s+SLEEP\s(.+)/ ){
			$sleeptime = $1;
		}elsif( $line =~ /END/ ){
			my $h = {};
			$h->{'RUN'} = $run;
			$h->{'_PRE_COND'} = $pre_cond;
			$h->{'_POST_COND'} = $post_cond;
			$h->{'TIMEOUT'} = $timeout;
			$h->{'SLEEP'} = $sleeptime;
			$stg[$stage] = $h;
	
			$in_stage = 0;
			$run = "NONE";   
			$timeout = 0;
			$pre_cond = "";
			$post_cond = "";
			$sleeptime = 0;
		};
	}else{
		if( $line =~ /^TEST_NAME\s+(.+)/ ){
			$test_name = $1;
		}elsif( $line =~ /^TOTAL_STAGES\s+(\d+)/ ){
			$total_stages = $1;
		}elsif( $line =~ /^REPEAT\s+(\d+)/ ){
			$repeat = $1;
		}elsif( $line =~ /^CREDENTIALS_INCLUDED\s+(\w+)/ ){
			$cred_included = $1;
		}elsif( $line =~ /^ENV_FILE\s+(.+)/ ){
			$env_file = $1;
		}elsif( $line =~ /^PRERUN/ ){
			$in_stage = 1;
			$stage = 0;
		}elsif( $line =~ /^POSTRUN/ ){
			$in_stage = 1;
			$stage = $total_stages + 1;
		}elsif( $line =~ /^FALLBACK/ ){
                        $in_stage = 1;
                        $stage = $total_stages + 2;
		}elsif( $line =~ /^STAGE(\d+)/ ){
			$in_stage = 1;
			$stage = $1;
		}elsif( $line =~ /^EUCA_VERSION\s+(.+)/ ){
			$euca_version = $1;
		}elsif( $line =~ /^REPEAT_PRERUN\s+(.+)/ ){
			$repeat_prerun = $1;
		}elsif( $line =~ /^EXIT_ON_FAIL\s+(.+)/ ){
			$exit_on_fail = $1;
		}elsif( $line =~ /^IGNORE_EXIT_CODE\s+(.+)/ ){
			$ignore_exit_code = $1;
		};
	};
};


############### OVERWRITE CONF WITH ARGV ########################

if( @ARGV > 0 ){
	$repeat = shift @ARGV;
};

if( @ARGV > 0 ){
	$cred_included = shift @ARGV;
};


#print "REPEAT\t" . $repeat . "\n";
#print "CRED_INCLUDED\t" . $cred_included . "\n";

print get_time() . "\t[TEST_REPORT]\tTEST Stage : Running the Test $test_name\n";
sleep(1);


############### RE_USED STAGES HANDLING #########################

for( my $si = 1; $si <= $total_stages; $si++ ){

	my $s = $stg[$si];

	my $check = $s->{'RUN'};
	my $check_argv = "";

	if( $check =~ /^TEST\s(.+)/ ){
		$check = $1;
		if( $check =~ /(.+?)\s(.+)/ ){
			$check = $1;
			$check_argv = $2;
		};

		my $this_case = 0;

		for( my $ssi = $si+1; $ssi <= $total_stages; $ssi++ ){
			my $ss = $stg[$ssi];
			my $check_ss = $ss->{'RUN'};
			my $check_argv_ss = "";
			if( $check_ss =~ /^TEST\s(.+)/ ){
                		$check_ss = $1;
                		if( $check_ss =~ /(.+?)\s(.+)/ ){
                        		$check_ss = $1;
					$check_argv_ss = $2;
                		};
				if( $check eq $check_ss ){

					my $this_case_str = sprintf("%03d", $this_case);

					if( $this_case == 0 ){
						my $stage_id = sprintf("%03d", $si);
						my $c_dir = $check  . "_No_" . $this_case_str;
                                                system("cp -r ../$check ../$c_dir");
						my_sed("TEST_NAME\t$check", "TEST_NAME\t$c_dir", "../$c_dir/" .$check. ".conf");
						system("mv ../$c_dir/" .$check. ".conf ../$c_dir/" .$c_dir. ".conf");
						if( $check_argv ne "" ){
							$s->{'RUN'} = "TEST $c_dir $check_argv";
						}else{
							$s->{'RUN'} = "TEST $c_dir";
						};

						$this_case = $this_case +1;
						$this_case_str = sprintf("%03d", $this_case);

                                        };

					my $stage_id2 = sprintf("%03d", $ssi);
					my $cc_dir = $check . "_No_" . $this_case_str;
					if( !(-e "$cc_dir") ){
						system("cp -r ../$check ../$cc_dir");
						my_sed("TEST_NAME\t$check", "TEST_NAME\t$cc_dir", "../$cc_dir/" .$check. ".conf");
						system("mv ../$cc_dir/" .$check. ".conf ../$cc_dir/" .$cc_dir. ".conf");
						if( $check_argv_ss ne "" ){
							$ss->{'RUN'} = "TEST $cc_dir $check_argv_ss";
						}else{
							$ss->{'RUN'} = "TEST $cc_dir";
						};
						$this_case = $this_case + 1;
					};
				};
			};
		};
		my $sss = $stg[$si];
		print $sss->{'RUN'} . "\n";
	};


};


############### Execution of Stages  #############################

#### remove the STATUS file ./status/test.stat
if( -e "./status/test.stat" ){
	system("rm ./status/test.stat");
};

#### remove all the files in ./artifacts
system("rm -f ./artifacts/*.out");

#### create a STATUS file
open( STAT, "> ./status/test.stat" ) or die $!;

print STAT "PREP\n";


#### ENV setup ###############################################

my $included_env = "source $ENV{'PWD'}/etc/default.env; ";

# get the credentials for the testee system   ... prob... not bash
if( $cred_included eq "YES" ){
	###	ADDED 010312	TAKEN OUT... CANNOT SOURCE EUCARC
#	if( -e "$ENV{'PWD'}/credentials/eucarc" ){
		$included_env .= "source $ENV{'PWD'}/credentials/eucarc; ";
#	}else{
#		print "\nWARNING: CANNOT LOCATE $ENV{'PWD'}/credentials/eucarc\n\n";
#	};
}else{
	# not sure ....dynamically load it ??
};

# process ENV file
if( $env_file ne "" ){
	$included_env = $included_env . "source $ENV{'PWD'}/" . $env_file . "; ";
};

my $bash_setup = "bash -c \"" . $included_env;


###	ANDY'S PATCH	ADDED 010412
if( -e "../shared/python" ){
	# Make python module sharing work
	my @pypaths = split(":", $ENV{'PYTHONPATH'});
	my $sharedpypath = `readlink -f "../shared/python"`;
	chomp($sharedpypath);
	push(@pypaths, $sharedpypath);
	$ENV{'PYTHONPATH'} = join(":", @pypaths);
};

#### STAGE INDEX AND POINTERS SETUP ############################

my $prefix = "";

# prepare outer-stage index
my $stage_prerun = 0;
my $stage_postrun = $total_stages+1;
my $stage_fallback = $total_stages+2;

# prepare points to outer-stages
my $ptr_prerun = $stg[0];
my $ptr_postrun = $stg[$total_stages+1];
my $ptr_fallback = $stg[$total_stages+2];

my $loop = 0;

##### PRERUN ################################################

if( $repeat_prerun eq "YES" || !( -e "./status/prerun.ran" ) ){

	print STAT "PRERUN\n";

	print "\n";
	print "-------------------------------------------------------------------------------\n";
	print "PRERUN\n";
	print "-------------------------------------------------------------------------------\n\n";

	if( process_stages("./prerun/", $ptr_prerun, $stage_prerun, $loop ) ){
		handle_fallback($ptr_fallback, $stage_fallback, $loop);			# if PRE-RUN fails, the test must EXIT.
		if( $exit_on_fail eq "YES" ){
			exit(1);
		}else{
			exit(0);
		};
	};	

	# write to ./status directory indicating the PRERUN has ran once
	system("touch ./status/prerun.ran");
};


##### MAIN STAGE LOOP ##########################################

while( $loop < $repeat ){

	print "\n";
	print "************************\n";
	print "Started Test Trial $loop\n";
	print "************************\n";

	for( my $s_index = 1; $s_index <= $total_stages; $s_index++ ){
	
		my $s = $stg[$s_index];
	
		print "\n";
		print "-------------------------------------------------------------------------------\n";
		print "[ Trial $loop ] Stage " . sprintf("%02d", $s_index) . "\n";
		print "-------------------------------------------------------------------------------\n\n";
		$prefix = "./stage" . sprintf("%02d", $s_index) . "/";

		print STAT "STAGE" . sprintf("%02d", $s_index) . "\n";
		if( process_stages($prefix, $s, $s_index, $loop ) ){
			
			#print get_time() . "\t[TEST_REPORT]\tTEST $test_name has FAILED at TRIAL $loop STAGE $s_index\n";

			handle_fallback($ptr_fallback, $stage_fallback, $loop);
			if( $exit_on_fail eq "YES" ){
				exit(1);
			}else{
				$s_index = $total_stages + 1;		# GET OUT THE LOOP	
			};
		};
	};
	
	print "\nEnded Test Trial $loop\n";

	$loop++;
};


###### POSTRUN ################################################

print STAT "POSTRUN\n";

print "\n";
print "-------------------------------------------------------------------------------\n";
print "POSTRUN\n";
print "-------------------------------------------------------------------------------\n";

if( process_stages("./postrun/", $ptr_postrun, $stage_postrun, $repeat-1 ) ){
	handle_fallback($ptr_fallback, $stage_fallback, $repeat-1 );
	if( $exit_on_fail eq "YES" ){
		exit(1);
	}else{
		exit(0);
	};
};

###### COMPLETED #################################################


print STAT "COMPLETED\n";
close(STAT);

#print "\nCOMPLETED TESTING\n";

print get_time() . "\t[TEST_REPORT]\tTEST Stage : Finished the Test $test_name\n";
sleep(1);

exit(0);

1;


###################################################### subroutines #######################################################


sub process_stages{

	my ($prefix, $s, $this_stage, $this_trial) = @_;

	if( $s->{'_PRE_COND'} ){
		print "===================\n";
		print "PRE-CONDITION CHECK\n";
		print "===================\n";

		my @checks = split( /;\s+/, $s->{'_PRE_COND'} );

		foreach my $check (@checks){
			#print "detected : "  . $check . "\n";
			$check =~ s/;//;
			if( $check =~ /^_/ ){
				print "\n" . get_time() . "\t";
				print "Running LIB SCRIPT ./lib/" . find_lib_script($check) . "\n";

				chdir("./lib");
				my $cmd = construct_cmd( "./" . find_lib_script($check) );
				timed_run($cmd, 1800 );
				chdir("$ENV{'PWD'}");
			}else{
				print "\n" . get_time() . "\t";
				print "Running USER SCRIPT $prefix$check\n";

				chdir("$prefix");

				if ( $check =~ /^java/ ){
					#skip
				}else{
					$check = "./" . $check;
				};

				my $cmd = construct_cmd("$check");
				timed_run($cmd, 1800 );
				chdir("$ENV{'PWD'}");
			};
			
			process_output( $check,  "pre_cond",  $this_stage, $this_trial, $display_option, 0 );
	
			if( check_exit_code($check, "pre_cond", $this_stage, $this_trial) ){
				return 1;
			};

		};
	};

	if( $s->{'RUN'} ){

		my $is_timed_out = 0;

		print "================\n";
		print "MAIN TEST SCRIPT\n";
		print "================\n";

		my $check = $s->{'RUN'};

		if( $check =~ /^NONE/ ){
			# do nothing
		}elsif( $check =~ /^TEST\s(.+)/ ){
			$check = $1;
			my $this_argv  = "";
			if( $check =~ /(.+?)\s(.+)/ ){
				$check = $1;
				$this_argv = $2;
			};
			print "\n" . get_time() . "\t";
			### copying this 2b_tested.lst to TEST directory
			system("cp ./input/2b_tested.lst ../$check/input/.");
			print "Running the TEST ../$check/run_test.pl ". $check . ".conf " . $this_argv . "\n";
			chdir("../$check");
			my $cmd = construct_cmd("./run_test.pl ". $check . ".conf " . $this_argv );
			$is_timed_out = timed_run($cmd, $s->{'TIMEOUT'} );
			chdir("$ENV{'PWD'}");
			process_output( $check,  "run",  $this_stage, $this_trial, $display_option, $is_timed_out );
		}else{
			if( $check =~ /^_/ ){
				print "\n" . get_time() . "\t";
                                print "Running LIB SCRIPT ./lib/" . find_lib_script($check) . "\n";

				chdir("./lib");
				my $cmd = construct_cmd( "./" . find_lib_script($check) );
				$is_timed_out = timed_run($cmd, $s->{'TIMEOUT'} );
				chdir("$ENV{'PWD'}");
			}else{
                                print "\n" . get_time() . "\t";
                                print "Running USER SCRIPT $prefix$check\n";

				chdir("$prefix");

                                if ( $check =~ /^java/ ){
                                        #skip
                                }else{
                                        $check = "./" . $check;
                                };

				my $cmd = construct_cmd( "$check" );
				$is_timed_out = timed_run($cmd, $s->{'TIMEOUT'} );
				chdir("$ENV{'PWD'}");
			};
			process_output( $check,  "run",  $this_stage, $this_trial, $display_option, $is_timed_out );
		};

		if( check_exit_code($check, "main_run", $this_stage, $this_trial) ){
			return 1;
		};

		if( $is_timed_out ){
			print "\n";
			print "\n" . get_time() . "\t[TEST_REPORT]\tFAILED ::";
			print " Command $check TIMED OUT !! at Trial $this_trial Stage $this_stage \n";
			print "\n";
			print "\n";
			return 1;
		};

	};

	if( $s->{'_POST_COND'} ){
		print "====================\n";
		print "POST_CONDITION CHECK\n";
		print "====================\n";

		my @checks = split( /;\s+/, $s->{'_POST_COND'} );

                foreach my $check (@checks){
			$check =~ s/;//;
			if( $check =~ /^_/ ){
				print "\n" . get_time() . "\t";
                                print "Running LIB SCRIPT ./lib/" . find_lib_script($check) . "\n";

				chdir("./lib");
				my $cmd = construct_cmd( "./" . find_lib_script($check) );
				timed_run($cmd, 1800 );
				chdir("$ENV{'PWD'}");
                        }else{
                                print "\n" . get_time() . "\t";
                                print "Running USER SCRIPT $prefix$check\n";

				chdir("$prefix");

                                if ( $check =~ /^java/ ){
                                        #skip
                                }else{
                                        $check = "./" . $check;
                                };

				my $cmd = construct_cmd("$check");
				timed_run($cmd, 1800 );
				chdir("$ENV{'PWD'}");
			};

			process_output( $check,  "post_cond",  $this_stage, $this_trial, $display_option, 0 );

			if( check_exit_code($check, "post_cond", $this_stage, $this_trial) ){
				return 1;
			};

                };
        };

	if( $s->{'SLEEP'} ){
                print "\nSLEEP for $s->{'SLEEP'} sec\n\n";
		sleep($s->{'SLEEP'});
        };


	print "-------------------------------------------------------------------------------\n";
	print "[ Trial $this_trial ] END of Stage $this_stage\n";
	print "-------------------------------------------------------------------------------\n";
	


	return 0;
};


sub construct_cmd{
	my $line = shift;
	my $cmd = $bash_setup . $line . "\"";
#	print $cmd . "\n";
	return $cmd;
};

sub find_lib_script{
	my $in = shift;
	my @lines = split( / /, $in );
	my $f = @lines[0];
	$f =~ s/^_//;
	opendir( DIR, "$ENV{'PWD'}/lib" ) or die $!;
	my @files = readdir(DIR);
	foreach my $file ( @files ){
		if( $file =~ /^$f\.(.+)$/ ){
			$lines[0] = $file;
			return join( " ", @lines);
		};
	};
	closedir( DIR );
	return "CANNOT_FIND_SCRIPT";
};



sub process_output{
	my ($script, $this_cond, $this_stage, $this_trial, $this_option, $is_timed_out ) = @_;

	print "\n";
	if( $this_option == 1 || $this_option == 3 ){

		if( $is_timed_out ){
			print "\n";
			print "\n" . get_time() . "\t[TEST_REPORT]\tFAILED ::";
                        print " Script $script TIMED OUT !! at Trial $this_trial Stage $this_stage \n";
			print "\n";
			print "\n";
		};

		if( was_outstr() ){
                        print "<<<<<<<<<<<<<<<<<<<<<<  STDOUT  >>>>>>>>>>>>>>>>>>>>>>>>>\n\n" . get_recent_outstr() . "\n";
			print "<<<<<<<<<<<<<<<<<<<  END of STDOUT  >>>>>>>>>>>>>>>>>>>>>\n";
                };
                if( was_errstr() ){
			print "\n";
                        print "<<<<<<<<<<<<<<<<<<<<<<  STDERR  >>>>>>>>>>>>>>>>>>>>>>>>>\n\n" . get_recent_errstr() . "\n";
			print "<<<<<<<<<<<<<<<<<<<  END of STDERR  >>>>>>>>>>>>>>>>>>>>>\n";
                };
	};

	if( $this_option == 2 || $this_option == 3 ){

		if( length( $script ) > 200 ){
			$script = substr($script, 0, 199);
		};

		if( $script =~ /^\.\// ){
			$script =~ s/\.\///;
		};

		$script =~ s/\//_slash_/g;
		$script =~ s/\s+/_/g;
		$script =~ s/\./_dot_/g;

		my $out_filename = "$ENV{'PWD'}/artifacts/trial-" . sprintf("%04d", $this_trial) . 
				"-stage-" . sprintf("%03d", $this_stage) .
				"-task-" . $this_cond . 
				"-script-" . $script . ".out";
	#	my $err_filename = "$ENV{'PWD'}/artifacts/trial-" . sprintf("%03d", $this_trial) .
                                "-stage-" . sprintf("%02d", $this_stage) .
                                "-script-" . $script . ".err";
	
		open( OUT, "> $out_filename" ) or die "Error : $!\t$out_filename doesn't exist\n";
	#	open( ERR, "> $err_filename" ) or die $!;

		if( $is_timed_out ){
			print OUT "\n";
			print OUT "\n" . get_time() . "\t[TEST_REPORT]\tFAILED ::";
                        print OUT " Script $script TIMED OUT !! at Trial $this_trial Stage $this_stage \n";
			print OUT "\n";
			print OUT "\n";
		};

		if( was_outstr() ){
			print OUT "<<<<<<<<<<<<<<<<<<<<<<  STDOUT  >>>>>>>>>>>>>>>>>>>>>>>>>\n\n" . get_recent_outstr() . "\n";
			print OUT "<<<<<<<<<<<<<<<<<<<  END of STDOUT  >>>>>>>>>>>>>>>>>>>>>\n";

			#print OUT "\n" . get_time() . "\n<<<<<<<  STDOUT  >>>>>>>\n" . get_recent_outstr() . "\n";
                        #print OUT get_recent_outstr() . "\n";
                };
                if( was_errstr() ){
                        print OUT "\n";
			print OUT "<<<<<<<<<<<<<<<<<<<<<<  STDERR  >>>>>>>>>>>>>>>>>>>>>>>>>\n\n" . get_recent_errstr() . "\n";
			print OUT "<<<<<<<<<<<<<<<<<<<  END of STDERR  >>>>>>>>>>>>>>>>>>>>>\n";

			#print OUT "\n". get_time() ."\n<<<<<<<  STDOUT  >>>>>>>\n" . get_recent_outstr() . "\n";
                        #print OUT get_recent_errstr() . "\n";
                };
		print OUT "\n";
		close(OUT);
	#	close(ERR);
	};
        print "\n";
	return 0;
};

sub check_exit_code{
	my( $check, $which_run, $this_stage, $this_trial ) = @_;
	my $rc = $? >> 8;

	if( $rc == 1 ){
		print get_time() . "\t[TEST_REPORT]\tTEST Stage : TEST $test_name SCRIPT ($which_run) $check has FAILED at TRIAL $this_trial STAGE $this_stage\n";
		sleep(1);
		if( $ignore_exit_code eq "YES" ){
			return 0;
		};
		return 1;
	};
	return 0;
};


sub handle_fallback{
	my( $ptr, $stage, $loop) = @_;
	print "\n";
	print "-------------------------------------------------------------------------------\n";
	print "FALLBACK\n";
	print "-------------------------------------------------------------------------------\n\n";
	print "\nRunning FALLBACK SCRIPT\n\n";

	chdir("$ENV{'PWD'}");
	process_stages("./fallback/", $ptr, $stage, $loop );

	open( FAILED, "> ./status/test.failed" ) or die $!;
	print FAILED get_time() . "\tTest was failed at Trial $loop Stage $stage\n"; 
	close( FAILED );

	#exit(1);
	return 0;
};


sub get_time{
        my ($sec,$min,$hour,$mday,$mon,$year,$wday, $yday,$isdst)=localtime(time);
        my $string = sprintf "[%4d-%02d-%02d %02d:%02d:%02d]", $year+1900,$mon+1,$mday,$hour,$min,$sec;
        return $string;
};



# To make 'sed' command human-readable
# my_sed( target_text, new_text, filename);
#   --->
#        sed --in-place 's/ <target_text> / <new_text> /' <filename>
sub my_sed{

        my ($from, $to, $file) = @_;

        $from =~ s/([\'\"\/])/\\$1/g;
        $to =~ s/([\'\"\/])/\\$1/g;

        my $cmd = "sed --in-place 's/" . $from . "/" . $to . "/' " . $file;

        system("$cmd");

        return 0;
};

1;

