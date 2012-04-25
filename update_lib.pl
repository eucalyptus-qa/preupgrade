#!/usr/bin/perl

$ENV{'TEST_HOME'} = "/exports/disk1/test_server";

print "Copying $ENV{'TEST_HOME'}/test_script/archive/lib/* to ./lib\n";
system("cp $ENV{'TEST_HOME'}/test_script/archive/lib/* ./lib/");

print "Copying $ENV{'TEST_HOME'}/test_script/archive/lib/run_test.pl to .\n";
system("cp $ENV{'TEST_HOME'}/test_script/archive/lib/run_test.pl .");

exit(0);




