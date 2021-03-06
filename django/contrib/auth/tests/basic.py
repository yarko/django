from django.test import TestCase
from django.utils.unittest import skipUnless
from django.contrib.auth.models import User, AnonymousUser
from django.contrib.auth import utils
from django.core.management import call_command
from StringIO import StringIO

try:
    import crypt as crypt_module
except ImportError:
    crypt_module = None


class BasicTestCase(TestCase):
    def test_user(self):
        "Check that users can be created and can set their password"
        u = User.objects.create_user('testuser', 'test@example.com', 'testpw')
        self.assertTrue(u.has_usable_password())
        self.assertFalse(u.check_password('bad'))
        self.assertTrue(u.check_password('testpw'))

        # Check we can manually set an unusable password
        u.set_unusable_password()
        u.save()
        self.assertFalse(u.check_password('testpw'))
        self.assertFalse(u.has_usable_password())
        u.set_password('testpw')
        self.assertTrue(u.check_password('testpw'))
        u.set_password(None)
        self.assertFalse(u.has_usable_password())

        # Check authentication/permissions
        self.assertTrue(u.is_authenticated())
        self.assertFalse(u.is_staff)
        self.assertTrue(u.is_active)
        self.assertFalse(u.is_superuser)

        # Check API-based user creation with no password
        u2 = User.objects.create_user('testuser2', 'test2@example.com')
        self.assertFalse(u.has_usable_password())

    def test_user_no_email(self):
        "Check that users can be created without an email"
        u = User.objects.create_user('testuser1')
        self.assertEqual(u.email, '')

        u2 = User.objects.create_user('testuser2', email='')
        self.assertEqual(u2.email, '')

        u3 = User.objects.create_user('testuser3', email=None)
        self.assertEqual(u3.email, '')

    def test_anonymous_user(self):
        "Check the properties of the anonymous user"
        a = AnonymousUser()
        self.assertFalse(a.is_authenticated())
        self.assertFalse(a.is_staff)
        self.assertFalse(a.is_active)
        self.assertFalse(a.is_superuser)
        self.assertEqual(a.groups.all().count(), 0)
        self.assertEqual(a.user_permissions.all().count(), 0)

    def test_superuser(self):
        "Check the creation and properties of a superuser"
        super = User.objects.create_superuser('super', 'super@example.com', 'super')
        self.assertTrue(super.is_superuser)
        self.assertTrue(super.is_active)
        self.assertTrue(super.is_staff)

    def test_createsuperuser_management_command(self):
        "Check the operation of the createsuperuser management command"
        # We can use the management command to create a superuser
        new_io = StringIO()
        call_command("createsuperuser",
            interactive=False,
            username="joe",
            email="joe@somewhere.org",
            stdout=new_io
        )
        command_output = new_io.getvalue().strip()
        self.assertEqual(command_output, 'Superuser created successfully.')
        u = User.objects.get(username="joe")
        self.assertEqual(u.email, 'joe@somewhere.org')

        # created password should be unusable
        self.assertFalse(u.has_usable_password())

        # We can supress output on the management command
        new_io = StringIO()
        call_command("createsuperuser",
            interactive=False,
            username="joe2",
            email="joe2@somewhere.org",
            verbosity=0,
            stdout=new_io
        )
        command_output = new_io.getvalue().strip()
        self.assertEqual(command_output, '')
        u = User.objects.get(username="joe2")
        self.assertEqual(u.email, 'joe2@somewhere.org')
        self.assertFalse(u.has_usable_password())


        new_io = StringIO()
        call_command("createsuperuser",
            interactive=False,
            username="joe+admin@somewhere.org",
            email="joe@somewhere.org",
            stdout=new_io
        )
        u = User.objects.get(username="joe+admin@somewhere.org")
        self.assertEqual(u.email, 'joe@somewhere.org')
        self.assertFalse(u.has_usable_password())


class PasswordUtilsTestCase(TestCase):

    def _test_make_password(self, algo):
        password = utils.make_password(algo, "foobar")
        self.assertTrue(utils.is_password_usable(password))
        self.assertTrue(utils.check_password("foobar", password))

    def test_make_unusable(self):
        "Check that you can create an unusable password."
        password = utils.make_password("any", None)
        self.assertFalse(utils.is_password_usable(password))
        self.assertFalse(utils.check_password("foobar", password))

    def test_make_password_sha256(self):
        "Check creating passwords with SHA256 algorithm."
        self._test_make_password("sha256")

    def test_make_password_sha1(self):
        "Check creating passwords with SHA1 algorithm."
        self._test_make_password("sha1")

    def test_make_password_md5(self):
        "Check creating passwords with MD5 algorithm."
        self._test_make_password("md5")

    @skipUnless(crypt_module, "no crypt module to generate password.")
    def test_make_password_crypt(self):
        "Check creating passwords with CRYPT algorithm."
        self._test_make_password("crypt")
