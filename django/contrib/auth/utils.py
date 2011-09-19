import hashlib
from django.utils.encoding import smart_str
from django.utils.crypto import constant_time_compare
from django.utils.tokens import HashToken, RandomToken

UNUSABLE_PASSWORD = '!' # This will never be a valid hash

def get_hexdigest(algorithm, salt, raw_password):
    """
    Returns a string of the hexdigest of the given plaintext password and salt
    using the given algorithm ('md5', 'sha1' or 'crypt').
    """
    raw_password, salt = smart_str(raw_password), smart_str(salt)
    if algorithm == 'crypt':
        try:
            import crypt
        except ImportError:
            raise ValueError('"crypt" password algorithm not supported in this environment')
        return crypt.crypt(raw_password, salt)

    if algorithm == 'sha256':
        # If we wanted, we could return base-62 digest (tests pass as of now);
        #  return HashToken(salt + raw_password).alphanumeric()
        # but processing is more, and we're not going to present this to anyone,
        #  so hex is fine, if not as dense.
        return HashToken(salt + raw_password).hex()
    elif algorithm == 'md5':
        return hashlib.md5(salt + raw_password).hexdigest()
    elif algorithm == 'sha1':
        return hashlib.sha1(salt + raw_password).hexdigest()
    raise ValueError("Got unknown password algorithm type in password.")


def check_password(raw_password, enc_password):
    """
    Returns a boolean of whether the raw_password was correct. Handles
    encryption formats behind the scenes.
    """
    parts = enc_password.split('$')
    if len(parts) != 3:
        return False
    algo, salt, hsh = parts
    return constant_time_compare(hsh, get_hexdigest(algo, salt, raw_password))

def is_password_usable(encoded_password):
    return encoded_password is not None and encoded_password != UNUSABLE_PASSWORD

def make_password(algo, raw_password):
    """
    Produce a new password string in this format: algorithm$salt$hash
    """
    if raw_password is None:
        return UNUSABLE_PASSWORD
    salt = RandomToken().alphanumeric()
    hsh = get_hexdigest(algo, salt, raw_password)
    return '%s$%s$%s' % (algo, salt, hsh)
