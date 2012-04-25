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


if( $ENV{'JAVA_HOME'} eq "" ){
	print "JAVA_HOME is not SET !\n";
	my $whereis = `whereis java`;
	my @output01 = split( /\s/ , $whereis );
	my $is_usr_bin_java = 0;
	foreach my $line01 ( @output01 ){
		if( $line01 =~ /\/usr\/bin\/java/ ){
			$is_usr_bin_java = 1;
		};
	};

	if( $is_usr_bin_java == 0 ){
		print "Cannot locate /usr/bin/java!!\n";
		exit(1);
	};

	my $link_java_01 = `ls -la /usr/bin/java`;
	chomp($link_java_01);
	my @output02 = split( /\s/ , $link_java_01 );
	my $alt_link = pop(@output02);
	my $link_java_02_cmd = "ls -la $alt_link";
	my $link_java_02 = `$link_java_02_cmd`;
	my @output03 = split( /\s/ , $link_java_02 );
	my $java_link = pop(@output03);
	chomp($java_link);
	my @output04 = split( /\//, $java_link );
	my $jvm_index = -1;
	for( my $i = 0; $i < @output04; $i++ ){
		if( $output04[$i] eq "jvm" ){
			$jvm_index = $i;
		};
	};

	if( $jvm_index == -1 ){
		print "Cannot locate /jvm in java path!\n";
		exit(1);
	};
	

	my $final_java_home = "";
	for( my $i = 0; $i <= $jvm_index+1; $i++ ){
		$final_java_home .= $output04[$i] . "/";
	};
	chop($final_java_home);

	$ENV{'JAVA_HOME'} = $final_java_home;

	# there must be a desinated file to update env value
	system("echo export JAVA_HOME=$final_java_home >> ../etc/default.env");
};

print "JAVA_HOME is set to $ENV{'JAVA_HOME'}\n";
exit(0);

1;

# <START_DESCRIPTION>
# NAME: _is_java_home
# LANGUAGE: perl
# USAGE: _is_jave_home
# REQUIREMENT : NONE
# DESCRIPTION : This script checks if ENV variable JAVA_HOME is set correctly....not fully implemented
# <END_DESCRIPTION>

