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

sub is_it_multi_clusters{
        open( TESTED, "< ../input/2b_tested.lst" ) or die $!;
        my $multi = 0;
        my $line;
        while( $line = <TESTED> ){
                chomp($line);
		if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
                        my $compo = $6;
                        while( $compo =~ /(\d+)(.+)/ ){
                                if( int($1) > $multi ){
                                        $multi = int($1);
                                };
                                $compo = $2;
                        };
                };
        };
        close(TESTED);
        return $multi;
};

sub get_this_cc_id{
	my $this_ip = shift @_; 
        my $id = -1;
        my $scan = `cat ../input/2b_tested.lst | grep $this_ip`;
        chomp($scan);
        if( $scan =~ /CC(\d+)/ ||  $scan =~ /NC(\d+)/ ){
                $id = int($1);
                $ENV{'MY_CC_ID'} = $id;
        };
        return $id;
};

sub get_this_priv_ip{
	my $input_ip = shift @_;
	my $this_cc_id = get_this_cc_id($input_ip);
	
	my $priv_ip = "10.10.";

	if( $input_ip =~ /192\.168\.(\d+)\.(\d+)/ ){
        	my $priv_group = 10 + $this_cc_id;
        	$priv_ip .= $priv_group . "." . $2;
        	$ENV{'PRIV_IP'} = $priv_ip;
	};

	return $priv_ip;
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

my $vmbroker_group = "";

$ENV{'EUCALYPTUS'} = "/opt/eucalyptus";

#### read the input list

my $index = 0;


read_input_file();


if( $source_lst[0] eq "PACKAGE" || $source_lst[0] eq "REPO" ){
	$ENV{'EUCALYPTUS'} = "";
};


### check for multi-clusters mode
$ENV{'IS_IT_MULTI'} = is_it_multi_clusters();


my $is_error = 0;

### Register Components
register_ws($clc_ip);
sleep(3);

for( my $i = 0; $i <= $max_cc_num; $i++){
	register_cc($clc_ip, $i);
	register_sc($clc_ip, $i);
};

my @vb_groups = split(",", $vmbroker_group);
foreach my $this_group (@vb_groups){
	register_vmbroker($clc_ip, $this_group);
};

print "\n";
print "\n";

if( $is_error == 1){
	print "\n";
	print "[TEST_REPORT]\tEUCALYPTUS REGISTRATION FAILED !!!\n\n";
	exit(1);
};
	
print "\n[TEST_REPORT]\tEUCALYPTUS REGISTRATION COMPLETED\n";

exit(0);

1;

#############################  SUBROUTINES  ##########################################


sub register_ws{
	my $this_clc_ip = $_[0];


	print "\n\n----------------------- Registering Walrus -----------------------\n";

	my $outstr = "";
	for( my $i = 0; $i < $index; $i++){
		if( does_It_Have($roll_lst[$i], "WS") ){
			my $ws_ip = $ip_lst[$i];

			print "\n";
			print "Walrus IP $ws_ip\n";
			print "$this_clc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-walrus $ws_ip \n";
	
			#Register Walrus
			print("ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-walrus $ws_ip\"\n");
			$outstr = `ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-walrus $ws_ip\"`;

			print $outstr;
			if( $outstr =~ /SUCCESS:/ ){
				print "\nRegistered Walrus $ws_ip successfully !\n\n";
			}else{
				print "\n[TEST_REPORT]\tFAILED to Register Walrus $ws_ip !!!\n\n";
				$is_error = 1;
#				exit(1);
			};
			sleep(30);
		};
	};
	return 0;
};


sub register_cc{

	my $this_clc_ip = $_[0];
	my $group = sprintf("%02d", $_[1]);

	my $outstr = "";
	for( my $i = 0; $i < $index; $i++){

		if( $roll_lst[$i] =~ /CC$group/ ){

			print "\n\n----------------------- Registering CC$group -----------------------\n";

			my $my_cc_ip = $ip_lst[$i];

			print "\n";
			print "CC$group IP $my_cc_ip\n";
			print "$this_clc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-cluster test$group $my_cc_ip\n";

			#Register CC
			print("ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-cluster test$group $my_cc_ip\"\n");
			$outstr = `ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-cluster test$group $my_cc_ip\"`;

			print $outstr;
			if( $outstr =~ /SUCCESS:/ ){
	        		print "\nRegistered Cluster $my_cc_ip successfully !\n\n";
			}else{
	        		print "\n[TEST_REPORT]\tFAILED to Register Cluster $my_cc_ip !!!\n\n";
				$is_error = 1;
#	        		exit(1);
			};
			sleep(30);

			register_nc($my_cc_ip, $group);
		};
	};

	return 0;
};



sub register_nc{
	my $my_cc_ip = $_[0];
	my $group = sprintf("%02d", $_[1]);

	my @my_nc_ips = split( / / , $nc_lst{"NC_$group"} );

	print "\n\n----------------------- Registering NC$group -----------------------\n";

	my $outstr = "";
	foreach my $my_nc_ip (@my_nc_ips){

		print "\n";
		print "NC$group IP $my_nc_ip\n";
		print "$my_cc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-nodes $my_nc_ip \n";
	
		#Register NCs		
		print("ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-nodes $my_nc_ip\"\n");
		$outstr = `ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-nodes $my_nc_ip\"`;

	        print $outstr;
	        if( $outstr =~ /\.\.\.done/ ){
			print "\nRegistered Node $my_nc_ip successfully !\n\n";
	        }else{
	                print "\n[TEST_REPORT]\tFAILED to Register Node $my_nc_ip !!!\n\n";
			$is_error = 1;
#			exit(1);
	        };
		sleep(30);
	};
	return 0;
};


sub register_sc{
	my $this_clc_ip = $_[0];
	my $group = sprintf("%02d", $_[1]);

	print "\n\n----------------------- Registering SC$group -----------------------\n";

	my $outstr = "";
	for( my $i = 0; $i < $index; $i++){
		if( $roll_lst[$i] =~ /SC$group/ ){
			my $my_sc_ip = $ip_lst[$i];

			print "\n";
			print "SC$group IP $my_sc_ip\n";
			print "$this_clc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-sc test$group $my_sc_ip \n";

			#Register Storage Control
			print("ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-sc test$group $my_sc_ip\"\n");
			$outstr = `ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-sc test$group $my_sc_ip\"`;

			print $outstr;
        		if( $outstr =~ /SUCCESS:/ ){
                		print "\nRegistered StorageController $my_sc_ip successfully !\n\n";
        		}else{
                		print "\n[TEST_REPORT]\tFAILED to Register StorageController $my_sc_ip !!!\n\n";
				$is_error = 1;
#                		exit(1);
        		};
			sleep(30);
		};
	};
	return 0;
};


sub register_vmbroker{
	my $this_clc_ip = $_[0];
	my $group = sprintf("%02d", $_[1]);

	print "\n\n----------------------- Registering VMwarebroker$group -----------------------\n";

	my $outstr = "";
	for( my $i = 0; $i < $index; $i++){
		if( $roll_lst[$i] =~ /CC$group/ ){
			my $my_vb_ip = $ip_lst[$i];

			print "\n";
			print "CC$group IP $my_vb_ip\n";
			print "$this_clc_ip :: $ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-vmwarebroker test$group $my_vb_ip \n";

			#Register Vmware Broker
			print("ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-vmwarebroker test$group $my_vb_ip\"\n");
			$outstr = `ssh -o StrictHostKeyChecking=no root\@$this_clc_ip \"$ENV{'EUCALYPTUS'}/usr/sbin/euca_conf --register-vmwarebroker test$group $my_vb_ip\"`;

			print $outstr;
        		if( $outstr =~ /SUCCESS:/ ){
                		print "\nRegistered VmwareBroker $my_vb_ip successfully !\n\n";
        		}else{
                		print "\n[TEST_REPORT]\tFAILED to Register VmwareBroker $my_vb_ip !!!\n\n";
				$is_error = 1;
#				exit(1);
        		};
			sleep(30);
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
			print "IP $1 [Distro $2, Version $3, Arch $4] is built from $5 with Eucalyptus-$6\n";

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

		};
	};

	close( LIST );

	chop($vmbroker_group);

	return 0;
};
