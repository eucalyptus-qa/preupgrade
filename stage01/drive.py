#!/usr/bin/python

import os
import re
import sys
import time

from euca_qa import helper
from euca_qa import euca_except_hook

class PreUpgrade(helper.AbstractHelper):
    def run(self):
        ret = 0
        for host in self.config['hosts']:
            if 'clc' in host.roles:
                if host.dist in ['centos', 'rhel'] and host.release.startswith('5.') and host.getVersion().startswith('eee-2.0'):
                    pyver = '2.5'
                else:
                    pyver = '2.6'

                ret |= host.putfile('synthetic_data.py', 'synthetic_data.py')
                ret |= host.run_command('i=20; while [ $i -gt 0 ]; do rm admin_cred.zip; euca_conf --get-credentials admin_cred.zip; if [ $( du admin_cred.zip | cut -f1 ) -gt 0 ]; then break; fi; sleep 3; i=$(( $i - 1 )); done')
                # This fails on 3.0 for some reason, but does not seem to break preupgrade
                host.run_command('unzip -o admin_cred.zip')
                if host.dist in ['centos', 'rhel', 'fedora']:
                    ret |= host.run_command('rpm -q euca2ools || yum install -y --nogpgcheck euca2ools')
                if host.dist in ['centos', 'rhel'] and host.release.startswith('5.') and pyver == '2.6':
                    # This is needed for things like euca-add-user to work
                    ret |= host.run_command('mkdir /root/bin; ln -s /usr/bin/python2.6 /root/bin/python');
                    ret |= host.run_command('source eucarc; export PATH=/root/bin:$PATH; /usr/bin/python2.6 ./synthetic_data.py populate')
                else:
                    ret |= host.run_command("source eucarc; /usr/bin/python%s ./synthetic_data.py populate" % pyver)
                # If the check here doesn't work, there's no point in trying the upgrade; 
                # something is already wrong
                # ret |= host.run_command("source eucarc; /usr/bin/python%s ./synthetic_data.py check" % pyver)
                break

        if ret > 0:
            print "[TEST_REPORT] FAILED to create fake data for preupgrade"
        else:
            print "[TEST_REPORT] SUCCESS"
        return ret

if __name__ == "__main__":
    sys.excepthook = euca_except_hook(False, True)
    prerun = helper.EnableDNS()
    if not prerun.config['hosts'][0].getVersion().startswith('3'):
        result = prerun.run()
        if result != 0:
            sys.exit(result)

    p = PreUpgrade()
    sys.exit(p.run())
