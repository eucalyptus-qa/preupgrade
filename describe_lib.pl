#!/usr/bin/perl

use strict;


opendir(LIB , "./lib") or die $!;


my @files = readdir(LIB);

my $fh;

my $line;

foreach my $file (@files){
	
	open( $fh, "< ./lib/" . $file ) or print "Cannot open the file $file\n";
	
	my $is_desc = 0;
	while( $line = <$fh> ){
		chomp($line);
		if( $line =~ /<START_DESCRIPTION>/ ){
			$is_desc = 1;
			print "\n";
		}elsif( $line =~ /<END_DESCRIPTION>/ ){
			$is_desc = 0;
			print "\n";
		}else{
			if( $is_desc ){
				print $line . "\n";
			};
		};
	};

	close( $fh );
};


closedir( LIB );

