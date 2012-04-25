#!/usr/bin/perl
use strict;

open (STDERR, ">&STDOUT");

print "\n";
print "CMD : ec2-describe-addresses\n\n";
system("ec2-describe-addresses");

print "\n";
print "CMD : ec2-describe-availability-zones\n\n";
system("ec2-describe-availability-zones");

print "\n";
print "CMD : ec2-describe-bundle-tasks\n\n";
system("ec2-describe-bundle-tasks");

print "\n";
print "CMD : ec2-describe-group\n\n";
system("ec2-describe-group");

print "\n";
print "CMD : ec2-describe-image-attribute\n\n";
system("ec2-describe-image-attribute");

print "\n";
print "CMD : ec2-describe-images\n\n";
system("ec2-describe-images");

print "\n";
print "CMD : ec2-describe-instances\n\n";
system("ec2-describe-instances");

print "\n";
print "CMD : ec2-describe-keypair\n\n";
system("ec2-describe-keypairs");

print "\n";
print "CMD : ec2-describe-regions\n\n";
system("ec2-describe-regions");

print "\n";
print "CMD : ec2-describe-reserved_instances\n\n";
system("ec2-describe-reserved-instances");

print "\n";
print "CMD : ec2-describe-instances-offerings\n\n";
system("ec2-describe-reserved-instances-offerings");

print "\n";
print "CMD : ec2-describe-snapshots\n\n";
system("ec2-describe-snapshots");

print "\n";
print "CMD : ec2-describe-volumes\n\n";
system("ec2-describe-volumes");

print "\n";
print "CMD : ec2-describe-availability-zones coredump\n\n";
system("ec2-describe-availability-zones coredump");
