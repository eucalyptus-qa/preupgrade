#!/usr/bin/env python

###################################################
#
#  This script populates various kinds of
#  objects (users, volumes, network rules, etc.)
#  into a Eucalyptus cloud, so that upgrades
#  can be tested.  
#
###################################################

import logging
import random
import re
import os
import sys
import subprocess
import tempfile
import time
import urllib
import urllib2

import boto
from boto.exception import S3ResponseError, S3CreateError
from boto import s3
from boto.s3.key import Key
from boto.ec2.regioninfo import RegionInfo

import bdb
import traceback
try:
    import epdb as debugger
except ImportError:
    import pdb as debugger

def euca_except_hook(debugger_flag, debug_flag):
    def excepthook(typ, value, tb):
        if typ is bdb.BdbQuit:
            sys.exit(1)
        sys.excepthook = sys.__excepthook__

        if debugger_flag and sys.stdout.isatty() and sys.stdin.isatty():
            if debugger.__name__ == 'epdb':
                debugger.post_mortem(tb, typ, value)
            else:
                debugger.post_mortem(tb)
        elif debug_flag:
            traceback.print_exception(typ, value, tb)
            sys.exit(1)
        else:
            print value
            sys.exit(1)

    return excepthook

# It would be nice to get rid of all of the print statements in favor
# of log messages; for now I'm just doing this to log object creation
objLog = '/tmp/activity.log'
log = logging.getLogger('objLog')
activity_handler = logging.FileHandler(objLog)
activity_handler.setFormatter(logging.Formatter('%(message)s'))
log.addHandler(activity_handler)
log.setLevel(logging.INFO)

boto.set_file_logger('boto', '/tmp/boto.log', level=logging.DEBUG)

arange = lambda x, y: [ chr(z) for z in range(ord(x), ord(y)) ]
rand_from_list = lambda x: x[random.randint(0, len(x)-1)]
random.seed()

euca_version = open('/etc/eucalyptus/eucalyptus-version', 'r').read().replace('eee-', '').strip()
ec2timeout = "60"
mode = "system"
host = "localhost"
objTypes = ['keypair', 'object', 'bucket', 'volume', 'snapshot', 'rule', 'group']
userlist = {}
accounts = {}
debug = 1
local_ips = set()
activity_log_version = 0

def find_default_sc():
    global local_ips
    ip_re = re.compile('.*inet\s+([0-9.]+)/')
    p = subprocess.Popen(['ip', 'addr', 'show'], stdout=subprocess.PIPE)
    stdout = p.communicate()[0]
    for line in stdout.split('\n'):
        m = ip_re.match(line)
        if m:
            local_ips.add(m.groups()[0])

    p = subprocess.Popen('euca-describe-storage-controllers', stdout=subprocess.PIPE)
    stdout = p.communicate()[0]
    fallback = ''
    for line in stdout.split('\n'):
        if not line:
            continue
        fields = re.sub('\s+', ' ', line).split(' ')
        if euca_version.startswith('3.'):
           if fields[3] in local_ips:
               return fields[1]
        elif fields[2] in local_ips:
            return fields[1]
        if fallback == '' or fields[1].endswith('00'):
            # This is terrible, but I don't really know how euca 2.x chooses
            # a default SC when multiple remote SCs exist.
            fallback = fields[1]
    return fallback

DEFAULT_SC = find_default_sc()

def gen_random_string(size):
    randstr = ""
    valid = arange('0', '9') + arange('a', 'z') + arange('A', 'Z')
    randstr = "".join([ rand_from_list(valid) for x in range(0,size) ])
    return randstr

def get_user_credentials(username, outfile):
    if euca_version.startswith('3.'):
        return get_user_credentials_v3(username, outfile)
    else:
        return get_user_credentials_v2(username, outfile)

def get_user_credentials_v2(username, outfile):
    userCode = None
    userCodeRE = re.compile('USER-CODE\s+(.*)\s+(.*)$')
    p = subprocess.Popen([ "euca-describe-users", username ],
                         stdout=subprocess.PIPE)
    out = p.communicate()[0]
    for line in out.split("\n"):
        m = userCodeRE.match(line)
        if m is not None:
            userCode = m.groups()[1]
            break
    if userCode is not None:
        p = subprocess.Popen([ "wget", "--no-check-certificate", "-O", outfile,
           "https://%s:8443/getX509?user=%s&code=%s" % (host, username, userCode) ])
        (out, err) = p.communicate()
        return
    else:
        print "Could not get credentials for %s" % username;
        sys.exit(1)

def get_user_credentials_v3(username, outfile):
    p = subprocess.Popen(["euca_conf", "--get-credentials", outfile, 
                          "--cred-account=%s" % username, "--cred-user=admin"])
    (out, err) = p.communicate()
    return

def add_user(username):
    account_id = 0
    if euca_version.startswith('3.'):
        p = subprocess.Popen(["euare-accountcreate", "-a", username], stdout=subprocess.PIPE)
        stdout = p.communicate()[0]
        account_id = stdout.split('\t')[1].strip()
    else:
        rc = subprocess.call(["euca-add-user", username])
    userDir = tempfile.mkdtemp(prefix='euca')
    time.sleep(2)
    get_user_credentials(username, "%s/creds.zip" % userDir);
    os.system("unzip %s/creds.zip -d %s" % (userDir, userDir))
    log.info('\t'.join(['USER', username, userDir]))
    p = Populater(username, userDir)
    p.setId(account_id)
    return p

def check_diffs(old, new, v2hack=False):
    # Given two sets of tuples, print the relative complements
    missing = old.difference(new)
    newfound = new.difference(old)
    if missing:
        print "MISSING:"
        print '\n'.join([ '\t'.join([ str(y) for y in x ]) for x in missing ])
    if newfound:
        print "NEW:"
        print '\n'.join([ '\t'.join([ str(y) for y in x ]) for x in newfound ])
    # HACK
    if v2hack and euca_version.startswith('2.') and not missing and newfound:
        return True
    if (missing or newfound):
        return False
    else:
        return True

class Populater(object):
    _ec2conn = None
    _s3conn = None
    id = 0

    def __init__(self, username, envdir):
        env = {}
        p = subprocess.Popen(["bash", "-c", "cd %s; source ./eucarc; env" % envdir],
                          stdout=subprocess.PIPE)
        out = p.communicate()[0].strip().split("\n")
        for line in out:
            (key, val) = line.split("=", 1)
            if key != "_":
                env[key] = val

        self.username = username
        self.envdir = envdir
        self.access_key = env['EC2_ACCESS_KEY']
        self.secret_key = env['EC2_SECRET_KEY']
        self.ec2_url = env['EC2_URL']
        self.s3_url = env['S3_URL']
        for objType in objTypes:
            setattr(self, objType, set())

    def setId(self, id):
        self.id = id

    @property
    def s3conn(self):
        if self._s3conn is None:
            urlparts = urllib2.urlparse.urlparse(self.s3_url)
            is_secure = (urlparts[0] == 'https') and True or False
            (host, port) = urllib.splitport(urlparts[1])
            if euca_version.startswith('2.') and boto.Version.startswith('1'):
                self._s3conn = s3.Connection(aws_access_key_id=self.access_key,
                                 aws_secret_access_key=self.secret_key,
                                 is_secure=is_secure,
                                 host=host,
                                 port=int(port),
                                 calling_format=s3.connection.OrdinaryCallingFormat(),
                                 path=urlparts[2])
            else:
                from boto.s3.connection import S3Connection
                self._s3conn = S3Connection(aws_access_key_id=self.access_key,
                                 aws_secret_access_key=self.secret_key,
                                 is_secure=is_secure,
                                 host=host,
                                 port=int(port),
                                 calling_format=s3.connection.OrdinaryCallingFormat(),
                                 path=urlparts[2])

        return self._s3conn

    @property
    def ec2conn(self):
        if self._ec2conn is None:
            urlparts = urllib2.urlparse.urlparse(self.ec2_url)
            is_secure = (urlparts[0] == 'https') and True or False
            (host, port) = urllib.splitport(urlparts[1])
            self._ec2conn = boto.connect_ec2(aws_access_key_id=self.access_key,
                                        aws_secret_access_key=self.secret_key,
                                        is_secure=is_secure,
                                        region=RegionInfo(None, "eucalyptus", host),
                                        port=int(port),
                                        path=urlparts[2])
        return self._ec2conn

    def add_ssh_keys(self, count):
        for i in range(0,count):
            keyname = gen_random_string(10)
            print "%s\tadding key %s" % (time.ctime(), keyname)
            keypair = self.ec2conn.create_key_pair(keyname)
            log.info("\t".join([self.username, 'KEYPAIR', 
                               keypair.name, keypair.fingerprint]))
            kp = os.path.join(self.envdir, keyname + ".priv")
            kpfile = open(kp, "w")
            kpfile.write(keypair.material)
            kpfile.close()
            os.chmod(kp, 0600)
        print "added %d keys" % count

    def add_rules_groups(self, count):
        grouplist = []
        for i in range(0,count):
            print "%s\tadding group..." % time.ctime()
            groupName = gen_random_string(10)
            grouplist.append(groupName)
            try:
                self.ec2conn.create_security_group(groupName, groupName)
                log.info('\t'.join([self.username, 'GROUP', groupName, groupName]))
            except:
                print "ERROR: failed to add group %s" % groupName
                raise
                sys.exit(1)
        print "added %d groups" % count
        return grouplist

    def add_network_rules(self, rulesGroup):
        # TODO: randomize this
        print "%s\tallowing ICMP and SSH\n" % time.ctime()
        if euca_version.startswith('3.') or not boto.Version.startswith('1'):
            self.ec2conn.authorize_security_group_deprecated(group_name = rulesGroup,
                src_security_group_name = None,
                src_security_group_owner_id = None,
                ip_protocol = "icmp",
                from_port = -1,
                to_port = -1,
                cidr_ip = "0.0.0.0/0")
        else:
            self.ec2conn.authorize_security_group(group_name = rulesGroup,
                src_security_group_name = None,
                src_security_group_owner_id = None,
                ip_protocol = "icmp",
                from_port = -1,
                to_port = -1,
                cidr_ip = "0.0.0.0/0")
        log.info('\t'.join([self.username, 'RULE', rulesGroup, "icmp", 
                            "-1:-1", "0.0.0.0/0"]))
        if euca_version.startswith('3.') or not boto.Version.startswith('1'):
            self.ec2conn.authorize_security_group_deprecated(group_name = rulesGroup,
                src_security_group_name = None,
                src_security_group_owner_id = None,
                ip_protocol = "tcp",
                from_port = 22,
                to_port = 22,
                cidr_ip = "0.0.0.0/0")
        else:    
            self.ec2conn.authorize_security_group(group_name = rulesGroup,
                src_security_group_name = None,
                src_security_group_owner_id = None,
                ip_protocol = "tcp",
                from_port = 22,
                to_port = 22,
                cidr_ip = "0.0.0.0/0")
        log.info('\t'.join([self.username, 'RULE', rulesGroup, "tcp", 
                            "22:22", "0.0.0.0/0"]))

    def add_buckets(self, count):
        # TODO: ACLs
        bucketList = []
        print "adding %d buckets" % count
        for i in range(0,count):
            thisgrant = rand_from_list(['READ', 'WRITE', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'])
            grantuser = rand_from_list([ x for x in userlist.keys() if x != self.username ])
            bucket = gen_random_string(6).lower()
            bucketList.append(bucket)
            print 'Creating bucket:', bucket
            b = self.s3conn.create_bucket(bucket)
            print 'Granting %s access to %s' % (thisgrant, grantuser)
            if euca_version in ['3.0.0', '3.0.1']:
                # RT 6383 requires us to pass ID as display_name for these versions
                b.add_user_grant(thisgrant, userlist[grantuser].access_key, display_name=userlist[grantuser].id)
            elif euca_version.startswith('3.'):
                # XXX: Maybe we should only pass ID now that the code works properly
                b.add_user_grant(thisgrant, userlist[grantuser].id, display_name=userlist[grantuser].username)
            else:
                # Using access_key as the second required parameter here is nonsense; we probably should just pass zero
                b.add_user_grant(thisgrant, userlist[grantuser].access_key, display_name=userlist[grantuser].username)
            log.info('\t'.join([self.username, 'BUCKET', bucket, thisgrant, grantuser]))
        return bucketList

    def add_objects(self, bucket, count, srcDir='/usr/bin'):
        # TODO: ACLs
        objectList = []
        canned_acl = 'private'

        bucket_instance = self.s3conn.get_bucket(bucket)
        for i in range(0,count):
            thisgrant= rand_from_list(['READ', 'READ_ACP', 'WRITE_ACP', 'FULL_CONTROL'])
            grantuser = rand_from_list([ x for x in userlist.keys() if x != self.username ])
            objectpath = rand_from_list(os.listdir(srcDir))
            print "adding %s to %s" % (os.path.join(srcDir, objectpath), bucket)
            obj = self.upload_object(bucket_instance, os.path.join(srcDir, objectpath), canned_acl)
            if euca_version in ['3.0.0', '3.0.1']:
                # RT 6383 requires us to pass ID as display_name for these versions
                obj.add_user_grant(thisgrant, userlist[grantuser].access_key, display_name=userlist[grantuser].id)
            elif euca_version.startswith('3.'):
                # XXX: Maybe we should only pass ID now that the code works properly
                obj.add_user_grant(thisgrant, userlist[grantuser].id, display_name=userlist[grantuser].username)
            else:
                # Using access_key as the second required parameter here is nonsense; we probably should just pass zero
                obj.add_user_grant(thisgrant, userlist[grantuser].access_key, display_name=userlist[grantuser].username)
            log.info('\t'.join([self.username, 'OBJECT', bucket, 
                                objectpath, thisgrant, grantuser]))

    def upload_object(self, bucket, object_filename, acl):
        k = Key(bucket)
        k.key = os.path.basename(object_filename)
        if euca_version.startswith('3.') or not boto.Version.startswith('1'):
            k.set_contents_from_filename(object_filename, policy=acl)
        else:
            object_file = open(object_filename, "rb")
            k.set_contents_from_file(object_file, policy=acl)
        return bucket.get_key(k.key)
      
    def add_volumes_and_snapshots(self, count):
        for z in self.ec2conn.get_all_zones():
            for i in range(0,count):
                volsize = random.randint(1,3)
                vol = self.ec2conn.create_volume(volsize, z.name)
                # XXX: HACK! Work around vol mysteriously changing during vol.update
                vol_id = vol.id
                vol_size = vol.size
                vol_zone = vol.zone
                sys.stdout.write("creating volume %s ... " % vol_id)
                sys.stdout.flush()
                while vol.status not in ['available', 'failed']:
                    time.sleep(3)
                    vol.update()
                    sys.stdout.write(vol.status + "...")
                if vol.status == 'available':
                    print "created volume " + vol_id
                    log.info('\t'.join([self.username, 'VOLUME', vol_id, str(vol_size), vol_zone]))
                    if random.randint(0,3) != 0:
                        time.sleep(1)
                        snap = vol.create_snapshot()
                        sys.stdout.write("creating snapshot %s ... " % snap.id)
                        sys.stdout.flush()
                        while snap.status not in ['completed', 'failed']:
                            time.sleep(3)
                            snap.update()
                        if snap.status == 'completed':
                            print "created snapshot " + snap.id
                            log.info('\t'.join([self.username, 'SNAPSHOT', snap.id, 
                                                snap.volume_id]))

    def add_data(self, objType, data):
        if objType == 'KEYPAIR' and euca_version.startswith('3.') and activity_log_version.startswith('2.'):
            data[0] = ''.join([self.username, data[0]])
        if objType == 'VOLUME' and euca_version.startswith('3.'):
            if data[2] == 'default':
                data[2] = DEFAULT_SC
        getattr(self, objType.lower()).add(tuple(data))

    def check_data(self, clean=False):
        result = True
        for objType in objTypes:
            try:
                print 'Checking %s' % objType
                result &= getattr(self, 'check_' + objType)(clean)
            except Exception, e:
                print "Exception in data check: ", e
                result = False
                if clean:
                    print "WARNING: not all objects were cleaned"
        return result

    def check_rule(self, clean=False):
        time.sleep(1)
        groups = self.ec2conn.get_all_security_groups()
        rules = set()
        for group in groups:
            if (self.id and group.owner_id != self.id) or \
               (not self.id and group.owner_id != self.username):
                continue
            for x in group.rules:
                for grant in x.grants:
                    if grant.owner_id:
                        rules.add((group.name, x.ip_protocol, '%s:%s' % (x.from_port, x.to_port),
                                  grant.owner_id))
                    elif grant.name:
                        rules.add((group.name, x.ip_protocol, '%s:%s' % (x.from_port, x.to_port),
                                  grant.name))
                    else:
                        rules.add((group.name, x.ip_protocol, '%s:%s' % (x.from_port, x.to_port),
                                  grant.cidr_ip))
                    if clean:
                        if euca_version.startswith('3.') or not boto.Version.startswith('1'): 
                            self.ec2conn.revoke_security_group_deprecated(group.name,
                                 grant.name, grant.owner_id,
                                 x.ip_protocol, x.from_port, x.to_port, grant.cidr_ip)
                        else:
                            self.ec2conn.revoke_security_group(group.name,
                                 group.owner_id, grant.name, grant.owner_id,
                                 x.ip_protocol, x.from_port, x.to_port, grant.cidr_ip)

        return check_diffs(self.rule, rules)

    def check_group(self, clean=False):
        # TODO
        time.sleep(1)
        if euca_version.startswith('3'):
            groups = set([(x.name, x.description) for x in self.ec2conn.get_all_security_groups() if x.owner_id == self.id])
        else:
            groups = set([(x.name, x.description) for x in self.ec2conn.get_all_security_groups() if x.owner_id == self.username])
        if clean:
            for x in groups:
                if not x[0].startswith('default'):
                    self.ec2conn.delete_security_group(x[0])
        return check_diffs(self.group, groups)

    def check_keypair(self, clean=False):
        kp = set([(x.name, x.fingerprint) for x in self.ec2conn.get_all_key_pairs()])
        if clean:
            for x in kp:
                self.ec2conn.delete_key_pair(x[0])
        return check_diffs(self.keypair, kp)

    def check_volume(self, clean=False):
        vols = set([(x.id, str(x.size), x.zone) for x in self.ec2conn.get_all_volumes() \
                    if x.status == 'available' ])
        if clean:
            for x in vols:
                self.ec2conn.delete_volume(x[0])
        return check_diffs(self.volume, vols, v2hack=(self.username=='admin'))

    def check_snapshot(self, clean=False):
        snaps = set([(x.id, x.volume_id) for x in self.ec2conn.get_all_snapshots()])
        if clean:
            for x in snaps:
                self.ec2conn.delete_snapshot(x[0])
        return check_diffs(self.snapshot, snaps, v2hack=(self.username=='admin'))

    def check_bucket(self, clean=False):
        buckets = set()
        account_to_user = dict([ (v, k) for (k,v) in accounts.items() ])
        ret = True
        host = urllib.splitport(urllib2.urlparse.urlparse(self.s3_url)[1])[0]
        for x in self.bucket:
            try:
                # Check bucket in DNS
                p = subprocess.Popen(['dig', '@127.0.0.1', '+short',
                                      '+nocmd', '+nocomments', 
                                      '%s.walrus.localhost' % x[0]],
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, stderr = p.communicate()
                if stdout.strip() != host:
                    print "%s does not resolve correctly in DNS" % x[0]
                    ret = True
                bucket = self.s3conn.get_bucket(x[0])
                # TODO: add support for more grants
                username = ''
                try:
                  for g in bucket.get_acl().acl.grants:
                    if g.display_name != self.username and \
                       g.display_name != self.id and \
                       g.id != self.id:
                        if euca_version in ['3.0.0', '3.0.1']:
                            username = account_to_user[g.display_name]
                        else:
                            username = g.display_name
                        if username == 'eucalyptus':
                            username = 'admin'
                    else:
                        continue
                    buckets.add((bucket.name, g.permission, username))
                except:
                    buckets.add((bucket.name, '', ''))
            except Exception, e:
                continue
        if clean:
            for x in buckets:
                self.s3conn.delete_bucket(x[0])
        return ret and check_diffs(self.bucket, buckets)

    def check_object(self, clean=False):
        objects = set()
        buckets = dict()
        account_to_user = dict([ (v, k) for (k,v) in accounts.items() ])
        buckets_to_try = set([ x[0] for x in self.object ])
        for x in buckets_to_try:
            try:
                bucket = self.s3conn.get_bucket(x)
                policy = bucket.get_acl()
                if policy.owner.display_name != self.username and \
                   policy.owner.id != self.id and \
                   policy.owner.display_name != self.id:
                    continue
                buckets[x] = bucket
            except Exception, e:
                continue
        keys = [ buckets[x[0]].get_key(x[1]) for x in self.object if buckets.has_key(x[0]) ]
        for k in keys:
            try:
                policy = k.get_acl()
            except:
                objects.add((k.bucket.name, k.name, '', ''))
                continue
            for g in policy.acl.grants:
                if g.display_name != self.username and \
                    g.display_name != self.id and \
                    g.id != self.id:
                     if euca_version in ['3.0.0', '3.0.1']:
                         username = account_to_user[g.display_name]
                     else:
                         username = g.display_name
                     if username == 'eucalyptus':
                         username = 'admin'
                     objects.add((k.bucket.name, k.name, g.permission, username))
        if clean:
            for x in objects:
                buckets[x[0]].delete_key(x[1])
        return check_diffs(self.object, objects)

def populate():
    # all config parsing should happen in a separate function
    netRE = re.compile("^NETWORK\s+(\S+)")
    try:
      for x in open("./seeds/2b_tested.lst", "r").readlines():
        m = netRE.match(x)
        if m:
            global mode
            mode = m.groups()[0].lower()
    except:
      pass
    print "Mode:\t%s\n\n" % mode
    managed = (mode not in ['system', 'static']) and 1 or 0

    if managed and False: # XXX Fix this
        numips = random.randint(0, 3)
        print "adding %d addrs"
        for i in range(0,numips):
            print "\tallocating ip..."
            # TODO: Change to a boto call
            rc = subprocess.call(["euca-allocate-address", ])
            if rc:
                print "ERROR: failed to allocate address"
                sys.exit(1)
        print "allocated %d addresses" % numips

    global userlist
    userlist['admin'] = Populater('admin', '.')
    if euca_version.startswith('3.'):
        p = subprocess.Popen(["euare-accountlist", ],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
        [ out, err ] = p.communicate()
        accounts = dict([ x.split(' \t', 1) for x in out.split('\n') if len(x) > 3 ])
        userlist['admin'].setId(accounts['eucalyptus'])

    # Log the version so we can understand the activity log
    # when reading it back in via the "check" function
    log.info('\t'.join(['VERSION', euca_version]))

    numusers = random.randint(3, 4)
    print "adding %s users" % numusers
    for i in range(0,numusers):
        username = gen_random_string(random.randint(4,15))
        if euca_version.startswith('3.'):
            username = username.lower()
        userlist[username] = add_user(username)
      
    # At this point, admin credentials should not be
    # in environment variables
    for envvar in ['S3_URL', 'EC2_URL', 'EC2_PRIVATE_KEY',
                   'EC2_CERT', 'EUCALYPTUS_CERT', 'EC2_ACCESS_KEY',
                   'EC2_SECRET_KEY', 'EC2_USER_ID', 'EUCA_KEY_DIR']:
        if os.environ.has_key(envvar):
            os.environ.pop(envvar)

    for user in userlist.keys():  
        u = userlist[user]
        u.add_ssh_keys(random.randint(1,3))
        grouplist = u.add_rules_groups(random.randint(1,2))
        for x in grouplist:
            u.add_network_rules(x)
        
        bucketList = u.add_buckets(random.randint(2,3))
        objList = {}
        for b in bucketList:
            objList[b] = u.add_objects(b, random.randint(1,3))

        for trial in [1, 2, 3]:
            # There's a heisenbug here.  Maybe we can get one
            # attempt out of three to work.  If not, move on.
            try:
                u.add_volumes_and_snapshots(random.randint(1,2))
                break
            except:
                continue

def check(clean=False):
    result = True
    userlist = {}
    userlist['admin'] = Populater('admin', '.')
    [ out, err ] = [ "", "" ]
    global accounts
    accounts = {}

    if euca_version.startswith('3'):
        p = subprocess.Popen(["euare-accountlist", ],
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)
        try:
            [ out, err ] = p.communicate()
            accounts = dict([ x.split(' \t', 1) for x in 
                              out.strip().split("\n") ])
        except:
            print "failed to parse euare-accountlist output:"
            print out
            if err:
                print >>sys.stderr, "Errors:"
                print >>sys.stderr, err
            print >>sys.stderr, "Aborting check"
            sys.exit(1)
        userlist['admin'].setId(accounts['eucalyptus'])

    o = open(objLog, "r")
    for line in o.readlines():
        fields = line.strip().split('\t')
        if fields[0] == 'VERSION':
            global activity_log_version
            activity_log_version = fields[1]
        elif fields[0] == 'USER':
            userfield = fields[1].lower()
            if euca_version.startswith('3') and not accounts.has_key(userfield):
                print "User %s is missing" % userfield
                continue
            userlist[userfield] = Populater(userfield, fields[2])
            # For HA, we need to make sure URLs point to active components
            userlist[userfield].ec2_url = userlist['admin'].ec2_url
            userlist[userfield].s3_url = userlist['admin'].s3_url
            if euca_version.startswith('3'):
                userlist[userfield].setId(accounts[userfield])
            continue
        elif userlist.has_key(fields[0]):
            userlist[fields[0].lower()].add_data(fields[1], fields[2:])
    for user in userlist.keys():
        userlist[user].add_data('GROUP', ['default', 'default group'])

    for user in userlist.values():
        if user.username == 'admin':
            continue
        print "Checking %s" % user.username
        result &= user.check_data(clean)
        if clean:
            if euca_version.startswith('3'):
                p = subprocess.Popen(["euare-accountdel", "-r", "-a", user.username ],
                                 stdout=subprocess.PIPE)
            else:
                p = subprocess.Popen(["euca-delete-user", user.username ],
                                 stdout=subprocess.PIPE)
            print p.communicate()[0]           

    # Admin is last because in "clean" mode I don't want to accidentally delete
    # other users' objects
    print "Checking admin"
    result &= userlist['admin'].check_data(clean)

    if result:
        print "COMPLETED"
    elif clean:
        print "CLEAN-UP COMPLETED"
    else:
        print "FAILED"
        sys.exit(1)

if __name__ == "__main__":
    sys.excepthook = euca_except_hook(False, True)
    if len(sys.argv) < 2:
        print "This script requires an argument"
    elif sys.argv[1] == 'populate':
        populate()
    elif sys.argv[1] == 'check':
        check()
    elif sys.argv[1] == 'clean':
        check(clean=True)
