#!/usr/bin/perl

use strict;
use Cwd;

$ENV{'PWD'} = getcwd();

system("rm -fr $ENV{'PWD'}/artifacts/*");
system("rm -fr $ENV{'PWD'}/credentials/*");
system("rm -fr $ENV{'PWD'}/status/*");
system("rm -fr $ENV{'PWD'}/etc/bin");

exit(0);


