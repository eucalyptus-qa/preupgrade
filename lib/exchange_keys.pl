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

my $max_cc_num = 0;

$ENV{'EUCALYPTUS'} = "/opt/eucalyptus";

#### read the input list

my $index = 0;

read_input_file();


sync_clc_key();

sync_cc_key();

exit(0);


################################  SUBROUTINES ########################################



sub sync_clc_key{
	for( my $i = 0; $i < $index; $i++){ 
		if( does_It_Have($roll_lst[$i], "CLC") ){
			my $clc_ip = $ip_lst[$i];

			# Disabling StrictHostKeyChecking on CLC machine
			system("ssh -o StrictHostKeyChecking=no root\@$clc_ip \"sed --in-place 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/'   /etc/ssh/ssh_config\" ");

			# remove if exists
			if( -e "./id_rsa.pub.clc"){
				system("rm -f ./id_rsa.pub.clc");
			};

			# Copying the pub RSA key of CLC machine to every machine, including itself 
			system("scp -o StrictHostKeyChecking=no root\@$clc_ip:/root/.ssh/id_rsa.pub ./id_rsa.pub.clc");

			foreach my $this_ip ( @ip_lst ){
				system("scp -o StrictHostKeyChecking=no ./id_rsa.pub.clc root\@$this_ip:/root/id_rsa.pub.clc"); 
				system("ssh -o StrictHostKeyChecking=no root\@$this_ip \"cat /root/id_rsa.pub.clc >> /root/.ssh/authorized_keys\" ");
			};
		};
	};
	system("rm -f ./id_rsa.pub.clc");
	return 0;
};


sub sync_cc_key{

	for( my $i = 0; $i <= $max_cc_num; $i++){ 
		my $group = sprintf("%02d", $i);
		
		for( my $i = 0; $i < $index; $i++){ 
			
			if( $roll_lst[$i] =~ /CC$group/ ){

				my $my_cc_ip = $ip_lst[$i];

				# disabling StrictHostKeyChecking on ALL CC machine
				system("ssh -o StrictHostKeyChecking=no root\@$my_cc_ip \"sed --in-place 's/#   StrictHostKeyChecking ask/   StrictHostKeyChecking no/'   /etc/ssh/ssh_config\" ");

				if( -e "./id_rsa.pub.cc"){
					system("rm -f ./id_rsa.pub.cc");
				};

				# Copying the pub RSA key of the CC machine to every machine, including itself
				system("scp -o StrictHostKeyChecking=no root\@$my_cc_ip:/root/.ssh/id_rsa.pub ./id_rsa.pub.cc");

				foreach my $this_ip ( @ip_lst ){
        				system("scp -o StrictHostKeyChecking=no ./id_rsa.pub.cc root\@$this_ip:/root/id_rsa.pub.cc");
        				system("ssh -o StrictHostKeyChecking=no root\@$this_ip \"cat /root/id_rsa.pub.cc >> /root/.ssh/authorized_keys\" ");
				};
			};
		};
	};

	system("rm -f ./id_rsa.pub.cc");

	return 0;
};


sub read_input_file{

	open( LIST, "../input/2b_tested.lst" ) or die "$!";
	my $line;
	while( $line = <LIST> ){
		chomp($line);

		if( $line =~ /^([\d\.]+)\t(.+)\t(.+)\t(\d+)\t(.+)\t\[(.+)\]/ ){
                	print "IP $1 [Distro $2, Version $3, Arch $4] was built from $5 with Eucalyptus-$6\n";
			if( !($2 eq "VMWARE" || $2 eq "WINDOWS") ){

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



# <START_DESCRIPTION>
# NAME: _exchange_keys
# LANGUAGE: perl
# USAGE: _exchange_keys
# REQUIREMENT : 2b_tested.lst file in ./input directory to specify IPs of test machines
# DESCRIPTION : This script disables SSH's StrictHostKeyCheck option for all the machines and copies id_rsa.pub key of CLC and CC machines to all the machines.
# <END_DESCRIPTION> 



