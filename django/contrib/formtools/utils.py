try:
    import cPickle as pickle
except ImportError:
    import pickle

from django.conf import settings
from django.utils.crypto import salted_hmac
from django.utils.tokens import HashToken


def security_hash(request, form, *args):
    """
    Calculates a security hash for the given Form instance.

    This creates a list of the form field names/values in a deterministic
    order, pickles the result with the SECRET_KEY setting, then takes a
    hash of that.
    """
    import warnings
    warnings.warn("security_hash is deprecated; use form_hmac instead",
                  DeprecationWarning)
    data = []
    for bf in form:
        # Get the value from the form data. If the form allows empty or hasn't
        # changed then don't call clean() to avoid trigger validation errors.
        if form.empty_permitted and not form.has_changed():
            value = bf.data or ''
        else:
            value = bf.field.clean(bf.data) or ''
        if isinstance(value, basestring):
            value = value.strip()
        data.append((bf.name, value))
        
    data.extend(args)
    data.append(settings.SECRET_KEY)

    # Use HIGHEST_PROTOCOL because it's the most efficient.
    pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)

    return HashToken(pickled).hex()


def form_hmac(form):
    """
    Calculates a security hash for the given Form instance.
    """
    data = []
    for bf in form:
        # Get the value from the form data. If the form allows empty or hasn't
        # changed then don't call clean() to avoid trigger validation errors.
        if form.empty_permitted and not form.has_changed():
            value = bf.data or ''
        else:
            value = bf.field.clean(bf.data) or ''
        if isinstance(value, basestring):
            value = value.strip()
        data.append((bf.name, value))

    pickled = pickle.dumps(data, pickle.HIGHEST_PROTOCOL)
    key_salt = 'django.contrib.formtools'
    return salted_hmac(key_salt, pickled).hexdigest()
