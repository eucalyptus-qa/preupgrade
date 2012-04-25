#!/usr/bin/perl
use strict;
use Cwd;

$ENV{'PWD'} = getcwd();

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

my $rev_no = 0;

my $max_cc_num = 0;

my $index = 0;

my $vmbroker_group  = "";

$ENV{'EUCALYPTUS'} = "/opt/eucalyptus";

#### read the input list
read_input_file();


if( $source_lst[0] eq "PACKAGE" || $source_lst[0] eq "REPO" ){
	$ENV{'EUCALYPTUS'} = "";
};

### Special Case for DEBIAN PACKAGE and REPO	041311
if( $distro_lst[0] eq "DEBIAN" ){
	if( $source_lst[0] eq "PACKAGE" || $source_lst[0] eq "REPO" ){
		print "\nSpecial Case - DEBIAN PACKAGE or REPO\n";
		print "Skipping 'start_components.pl' Process\n";
		exit(0);
	};
};


### Start Eucalyptus Components

my $is_error = 0;

for( my $i = 0; $i <= $max_cc_num; $i++){
	start_cc($i);
	start_nc($i);
};

print "\n\n----------------------- Enabling Cloud Components -----------------------\n";

enable_cloud();

enable_walrus();

enable_sc();

enable_vmbroker();

start_cloud_components();

print "\n\n";

if( $is_error == 1 ){

	print "\n[TEST_REPORT]\tFAILED TO START SOME OF THE COMPONENETS !!!\n\n";
	exit(1);
};

print "\n[TEST_REPORT]\tALL THE COMPONENTS HAVE BEEN STARTED SUCCESSFULLY\n\n";


exit(0);





###################### SUBROUTINES  ########################################

sub start_cc{

	my $group = sprintf("%02d", $_[0]);

	print "\n\n----------------------- Start CC$group -----------------------\n";
	print "\nStarting CC Group $group\n";

	my $outstr = "";
	for( my $i = 0; $i < $index; $i++){

		if( $roll_lst[$i] =~ /CC$group/ ){

			my $my_cc_ip = $ip_lst[$i];

	                print "\n$my_cc_ip :: $ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cc start\n";
                	#STARTING CC
                	print("ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cc start\"\n");
	        	$outstr = `ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cc start\"`;

	        	print $outstr;
	        	if( $outstr =~ /done/ || $outstr =~ /Enabling IP/ ){
	        	        print "\nStarted CC $my_cc_ip successfully !\n";
	        	}else{
	        	        print "\n[TEST_REPORT]\tFAILED to Start CC $my_cc_ip !!\n";
	        	        $is_error = 1;
				#exit(1);
	        	};
			sleep(10);
		};
	};

	return 0;
};

sub start_nc{

	my $group = sprintf("%02d", $_[0]);

	print "\n\n----------------------- Start NC$group -----------------------\n";
	print "\nStarting NC Group $group\n";

	my $outstr = "";

	my @my_nc_ips = split( / / , $nc_lst{"NC_$group"} );
	foreach my $my_nc_ip (@my_nc_ips){
		print "\n$my_nc_ip :: $ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-nc start\n";
		
		#Start NCs
		print("ssh -o StrictHostKeyChecking=no root\@$my_nc_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-nc start\"\n");
		$outstr = `ssh -o StrictHostKeyChecking=no root\@$my_nc_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-nc start\"`;

		print $outstr;
                if( $outstr =~ /done/ || $outstr =~ /Enabling IP/ ){
			print "\nStarted NC $my_nc_ip successfully !\n";
		}else{
			print "\n[TEST_REPORT]\tFAILED to Start NC $my_nc_ip !!\n";
			$is_error = 1;
			#exit(1);
                };
			sleep(10);
	};
	return 0;
};


sub enable_cloud{

	for( my $i = 0; $i < $index; $i++){
		if( does_It_Have($roll_lst[$i], "CLC") ){
			my $clc_ip = $ip_lst[$i];
			print "$clc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable cloud\n";
        		#ENABLING CLC
        		system("ssh -o StrictHostKeyChecking=no root\@$clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable cloud\" ");
			sleep(1);
		};
	};

	return 0;
};

sub enable_walrus{

	for( my $i = 0; $i < $index; $i++){
		if( does_It_Have($roll_lst[$i], "WS") ){
			my $ws_ip = $ip_lst[$i];
			print "$ws_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable walrus\n";

	        	#Enabling Walrus
        		system("ssh -o StrictHostKeyChecking=no root\@$ws_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable walrus\" ");
			sleep(1);
		};
	};

	return 0;
};


sub enable_sc{

	for( my $i = 0; $i < $index; $i++){
		if( does_It_Have($roll_lst[$i], "SC") ){
			my $my_sc_ip = $ip_lst[$i];
			print "$my_sc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable sc\n";

                	#ENABLING Storage Control
			system("ssh -o StrictHostKeyChecking=no root\@$my_sc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable sc\" ");
			sleep(1);
		};
	};
	
	return 0;
};


sub enable_vmbroker{

	my @my_group = split(",", $vmbroker_group);

	for( my $i = 0; $i < $index; $i++){
		if( does_It_Have($roll_lst[$i], "CC") ){
			my $is_vmbroker = 0;
			if( $roll_lst[$i] =~ /CC(\d+)/ ){
				my $this_group = $1;
				foreach my $g (@my_group){
					if( $g == $this_group ){
						$is_vmbroker = 1;
						$roll_lst[$i] .= " VB" . sprintf("%02d", $this_group ); 
					};
				};

			};

			if( $is_vmbroker == 1 ){
				my $cc_ip = $ip_lst[$i];
				print "$cc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable vmwarebroker\n";
        			#ENABLING VMWAREBROKER
        			system("ssh -o StrictHostKeyChecking=no root\@$cc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --enable vmwarebroker\" ");
				sleep(1);
			};
		};
	};

	return 0;
};


sub start_cloud_components{

	my $outstr = "";
	for( my $j = 0; $j < $index; $j++ ){
		my $this_ip = $ip_lst[$j];
		my $this_roll = $roll_lst[$j];

		if( does_It_Have( $this_roll, "CLC") || does_It_Have( $this_roll, "SC") || does_It_Have( $this_roll, "WS") || does_It_Have( $this_roll, "VB")  ){

			print "\n\n----------------------- Start Cloud $this_ip [ $this_roll ] -----------------------\n";

			print "\n$this_ip :: $ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cloud start\n";
	
			#Starting CLOUD
			print("ssh -o StrictHostKeyChecking=no root\@$this_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cloud start\"\n");
			$outstr = `ssh -o StrictHostKeyChecking=no root\@$this_ip \"$ENV{'EUCALYPTUS'}/etc/init.d/eucalyptus-cloud start\"`;

			print $outstr;
			if( $outstr =~ /done/ ){
				print "Started CLOUD Components $this_ip successfully !\n";
			}else{
				sleep(3);
				my $check_ps = `ssh -o StrictHostKeyChecking=no root\@$this_ip \"ps aux | grep euca | grep cloud\"`;

				print $check_ps;

				if( $check_ps =~ /eucalyptus-cloud/ ){
					print "\nStarted CLOUD Components $this_ip successfully !\n";
				}else{
        	                        print "\n[TEST_REPORT]\tFAILED to Start CLOUD Components $this_ip !!\n";
		        	        $is_error = 1;
					#exit(1);
				};
			};
			sleep(5);
		};
	};
	return 0;
};




sub read_input_file{

	open( LIST, "../input/2b_tested.lst" ) or die "$!";
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
	
			}elsif( $2 eq "VMWARE" ){
				my $this_roll = $6;
				if( does_It_Have($this_roll, "NC") ){
                                        if( $this_roll =~ /NC(\d+)/ ){
						if( !($vmbroker_group =~ /$1,/) ){
							$vmbroker_group .= $1 . ",";
						};
					};
				};
			};

	        }elsif( $line =~ /^BZR_REVISION\s+(\d+)/  ){
			$rev_no = $1;
			print "REVISION NUMBER is $rev_no\n";
		};
	};

	close( LIST );

	chop($vmbroker_group);

	return 0;
};
