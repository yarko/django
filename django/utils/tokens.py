"""
Django's standard token library and utilities. 
"""

import hashlib
import string
import random

try:
    random = random.SystemRandom()
except NotImplementedError:
    random = random.random()

"""
Character sets for the various tokens and hashes.
"""
DIGITS = string.digits
UPPERCASE = string.uppercase
LOWERCASE = string.lowercase
HEX = string.digits + 'abcdef'
ALPHANUMERIC = string.digits + string.uppercase + string.lowercase
LOWER_ALPHANUMERIC = string.digits + string.lowercase
# remove for human consumption - we don't want confusion between letter-O and zero, etc.
# effectively: for i in 'iIloO01': x.remove(i)
READABLE_ALPHABET = '23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijklmnpqrstuvwxyz'

DEFAULT_TOKEN_LENGTH = 32

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
    
    def hex(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the HEX character sets.
        """
        return self._build_token(HEX, length)
    
    def readable_alphabet(self, length=DEFAULT_TOKEN_LENGTH):
        """
        Creates a randomized token consisting of the READABLE_ALPHABET character set.
        """
        return self._build_token(READABLE_ALPHABET, length)
    
    def _build_token(self, character_set, length):
        """
        Builds a random token of the specified length using the characters available in the specified character set.
        """
        return ''.join([random.choice(character_set) for i in xrange(length)])


class HashToken():
    """
    Return a token useful for a hash (that is, a token whose generation is repeatable)
    """
    def __init__(self, value=''):
        self._hash = hashlib.sha256(value)

    def digits(self):
        return _build_token(DIGITS)
        
    def hex(self):
        """ Outputs a base 16 string. """
        return self._hash.hexdigest()
    
    def digest(self):
        """ Returns the string digest. """
        return self._hash.digest()
    
    def alphanumenric(self, casesensitive=True):
        return _build_token(ALPHANUMERIC)
    
    def lower_alphanumeric(self):
        """
        Creates a randomized token consisting of the LOWER_ALPHANUMERIC character sets.
        """
        return self._build_token(LOWER_ALPHANUMERIC)
    
    def readable_alphabet(self):
        """
        Creates a randomized token consisting of the READABLE_ALPHABET character set.
        """
        return self._build_token(READABLE_ALPHABET)
    
    def _build_token(self, alphabet):
        """ Outputs our hash to an alphabet specified string. """
        hextoken = self._hash.hexdigest()
        converter = BaseConverter(alphabet)
        return converter.encode(int(hextoken, 16))

    def update(self, value):
        self._hash.update(value)


###
# Migrated from contrib.auth.tokens:
###


class PasswordResetTokenGenerator(object):
    """
    Strategy object used to generate and check tokens for the password
    reset mechanism.
    """
    def make_token(self, user):
        """
        Returns a token that can be used once to do a password reset
        for the given user.
        """
        return self._make_token_with_timestamp(user, self._num_days(self._today()))

    def check_token(self, user, token):
        """
        Check that a password reset token is correct for a given user.
        """
        # Parse the token
        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = BaseConverter(LOWER_ALPHANUMERIC).decode(ts_b36)
            
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit
        if (self._num_days(self._today()) - ts) > settings.PASSWORD_RESET_TIMEOUT_DAYS:
            return False

        return True

    def _make_token_with_timestamp(self, user, timestamp):
        # timestamp is number of days since 2001-1-1.  Converted to
        # base 36, this gives us a 3 digit string until about 2121
        ts_b36 = BaseConverter(LOWER_ALPHANUMERIC).encode(timestamp)

        # By hashing on the internal state of the user and using state
        # that is sure to change (the password salt will change as soon as
        # the password is set, at least for current Django auth, and
        # last_login will also change), we produce a hash that will be
        # invalid as soon as it is used.
        # We limit the hash to 20 chars to keep URL short
        key_salt = "django.contrib.auth.tokens.PasswordResetTokenGenerator"
        value = unicode(user.id) + \
            user.password + user.last_login.strftime('%Y-%m-%d %H:%M:%S') + \
            unicode(timestamp)
        hash = salted_hmac(key_salt, value).hexdigest()[::2]
        return "%s-%s" % (ts_b36, hash)

    def _num_days(self, dt):
        return (dt - date(2001,1,1)).days

    def _today(self):
        # Used for mocking in tests
        return date.today()

default_token_generator = PasswordResetTokenGenerator()
