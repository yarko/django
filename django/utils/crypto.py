"""
Django's standard crypto functions and utilities.
"""

from django.conf import settings
from django.utils.baseconv import BaseConverter
import string
import hashlib
import hmac
import random
try:
    random = random.SystemRandom()
except NotImplementedError:
    random = random.random()

    
#ALPHABET = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

# Alphabet naming:


## imported from string:
# digits
# lowercase
# uppercase

DIGITS = string.digits
UPPERCASE = string.uppercase
LOWERCASE = string.lowercase
HEX = string.digits + 'abcdef'
ALPHANUMERIC = string.digits + string.uppercase + string.lowercase
LOWER_ALPHANUMERIC = string.digits + string.lowercase
# remove for human consumption - we don't want confusion between letter-O and zero
# effectively: for i in 'ilIoO01': x.remove(i)
READABLE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz'


DEFAULT_TOKEN_LENGTH = 32




def base62_encode(num, alphabet=digits+letters):
    """Encode a number in Base X

    `num`: The number to encode
    `alphabet`: The alphabet to use for encoding
    """
    if (num == 0):
        return alphabet[0]
    arr = []
    base = len(alphabet)
    while num:
        rem = num % base
        num = num // base
        arr.append(alphabet[rem])
    arr.reverse()
    return ''.join(arr)

class RandomToken():
    """
    Object that creates randomized token.
    """
    def digits(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the DIGIT character set.
        """
        return self._build_token(DIGITS, length)
        
    def alphanumeric(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the general ALPHANUMERIC character sets.
        """
        return self._build_token(ALPHANUMERIC, length)
    
    def lower_alphanumeric(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the LOWER_ALPHANUMERIC character sets.
        """
        return self._build_token(LOWER_ALPHANUMERIC, length)
    
    def readable_alphanumeric(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the READABLE_ALPHABET character set.
        """
        return self._build_token(READABLE_ALPHABET, length)
    
    def _build_token(self, character_set, length):
        """
        Builds a random token of the specified length using the characters available in the specified character set.
        """
        return ''.join([random.choice(character_set) for i in range(length)])
        
class Base_Token():
    def __init__(self, value=None, random=False):
        if random:
            self._hash = hashlib.md5(random.getrandbits(256))
        else:
            self._hash = hashlib.md5(value)

    def base16(self, length=None):
        """
        Outputs our hash to a base 16 string.
        """
        return self._hash.hexdigest()[:length]

    def base62(self, length=None):
        """
        Outputs our hash to a base 62 string.
        """
        base16 = self._hash.hexdigest()
        base10 = int(base16, 16)
        

        # return base62.encode...
        # return base62_encode(base10)[:length]
        

    def update(self, value):
        self._hash = self._hash.update(value)


class HashToken(BaseToken):
    """
    Use for reproducible hash patterns
    """

class RandomToken(BaseToken):
    """
    Use for receiving random hash tokens
    """
    
    

def salted_hmac(key_salt, value, secret=None):
    """
    Returns the HMAC-SHA1 of 'value', using a key generated from key_salt and a
    secret (which defaults to settings.SECRET_KEY).

    A different key_salt should be passed in for every application of HMAC.
    """
    if secret is None:
        secret = settings.SECRET_KEY

    # We need to generate a derived key from our base key.  We can do this by
    # passing the key_salt and our base key through a pseudo-random function and
    # SHA1 works nicely.
    key = hashlib.sha1(key_salt + secret).digest()

    # If len(key_salt + secret) > sha_constructor().block_size, the above
    # line is redundant and could be replaced by key = key_salt + secret, since
    # the hmac module does the same thing for keys longer than the block size.
    # However, we need to ensure that we *always* do this.
    return hmac.new(key, msg=value, digestmod=hashlib.sha1)

def constant_time_compare(val1, val2):
    """
    Returns True if the two strings are equal, False otherwise.

    The time taken is independent of the number of characters that match.
    """
    if len(val1) != len(val2):
        return False
    result = 0
    for x, y in zip(val1, val2):
        result |= ord(x) ^ ord(y)
    return result == 0
