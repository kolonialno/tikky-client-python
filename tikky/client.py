import base64
import logging

import requests

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

logger = logging.getLogger(__name__)


class TikkyError(RuntimeError):
    pass


class TikkyClient:
    """
    A wrapper around the requests library, and some simple crypto.

    Invoke the client's API methods using a context manager to get authorized calls:

        >>> with tikky_client: tikky_client.method()

    Auth tokens are kept within each context manager block, so do as much at once as possible
    to minimize the number of HTTP calls. Optionally, see __enter__ and __exit__ for examples
    of what to replicate if you require more complex auth sessions.
    """

    # Auth is managed using the session object.
    session = None

    # The cipher is required to decrypt lock keys. It should be an instance
    # of the RSA protocol's PKCS#1 OAEP implementation.
    #
    # See https://www.dlitz.net/software/pycrypto/api/current/Crypto.Cipher.PKCS1_OAEP-module.html
    cipher = None

    # Set mock to True to return mock data from the API.
    #
    # Note: Decrypting mock keys will not work -- they're entrypted using a mock public key.
    mock = False

    def __init__(self, email, password, private_key=None, env='prod'):

        self.base_url = 'https://%s.tikky.io/api/partners/v1' % env

        # An RSA private key must be supplied to decrypt lock keys
        if private_key:
            rsa_key = RSA.importKey(private_key.strip())
            self.cipher = PKCS1_OAEP.new(rsa_key)

        self.email = email
        self.password = password

    ######################
    # Session management #
    ######################

    def init_session(self):
        """
        Starts an authorized session to use in subsequent calls.
        """

        self.session = requests.Session()
        self.session.auth = TikkyAuth(
            base_url=self.base_url,
            email=self.email,
            key=self.password,
        )

    ###############
    # API methods #
    ###############

    def users(self):

        url = self._url('/users')

        return self.get(url).json()

    # Accesses

    def accesses(self):

        url = self._url('/accesses')

        return self.get(url).json()

    def create_access(self, lock_id, start_date, end_date, order_number, product_image_url):

        url = self._url('/accesses')

        return self.post(url, {
            'lockId': lock_id,
            'startDate': start_date.isoformat(),
            'endDate': end_date.isoformat(),
            'orderNumber': order_number,
            'productImageUrl': product_image_url,
        }).json()

    def get_access(self, access_id):

        url = self._url('/accesses/%(access_id)s', access_id=access_id)

        return self.get(url).json()

    def delete_access(self, access_id):

        url = self._url('/accesses/%(access_id)s', access_id=access_id)

        return self.delete(url).ok

    def set_access_activated(self, access_id):

        url = self._url('/accesses/%(access_id)s/activated', access_id=access_id)

        return self.put(url).ok

    def set_access_completed(self, access_id):

        url = self._url('/accesses/%(access_id)s/completed', access_id=access_id)

        return self.put(url).ok

    def fetch_key(self, access_id):

        url = self._url('/accesses/%(access_id)s/key', access_id=access_id)

        return self.get(url).json()

    def decrypt_key(self, base64_key):

        if not self.cipher:
            raise RuntimeError('no rsa private key supplied')

        encrypted_data = base64.b64decode(base64_key)
        return self.cipher.decrypt(encrypted_data)

    def fetch_and_decrypt_key(self, access_id):

        base64_key = self.fetch_key(access_id)['key']
        return self.decrypt_key(base64_key)

    #########################
    # Context manager usage #
    #########################

    def __enter__(self):
        """
        Start an autorized session.
        """

        if not self.session:
            self.init_session()

        return self

    def __exit__(self, *args):
        """
        Close the current session.
        """

        if self.session:
            self.session.close()
            self.session = None

    #####################
    # Request utilities #
    #####################

    def _url(self, path='/', **params):

        url = self.base_url + (path % params)

        if self.mock:
            url += '?mock=true'

        return url

    def _handle_response(self, response):

        if not response.ok:

            logger.warning('Got a non-ok respons from Tikky: %r', response.json())

            raise TikkyError(response.json())

        return response

    def _perform_request(self, request_fn):

        if not self.session:
            raise RuntimeError('Session not initialized. Make sure you are using a context manager.')

        return self._handle_response(request_fn())

    def get(self, *args, **kwargs):

        return self._perform_request(
            lambda: self.session.get(*args, **kwargs)
        )

    def post(self, *args, **kwargs):

        return self._perform_request(
            lambda: self.session.post(*args, **kwargs)
        )

    def put(self, *args, **kwargs):

        return self._perform_request(
            lambda: self.session.put(*args, **kwargs)
        )

    def patch(self, *args, **kwargs):

        return self._perform_request(
            lambda: self.session.patch(*args, **kwargs)
        )

    def delete(self, *args, **kwargs):

        return self._perform_request(
            lambda: self.session.delete(*args, **kwargs)
        )


class TikkyAuth(requests.auth.AuthBase):
    """
    Custom token-based authorization. Each token is valid for 1 hour.
    """

    token = None

    def __init__(self, base_url, email, key):

        self.base_url = base_url

        # Pre-construct the autorization payload
        self.auth_data = {
            'email': email,
            'key': key,
        }

    def _fetch_token(self):
        """
        Fetch the auth token by posting to `/sessions`.
        """

        return requests.post(
            self.base_url + '/sessions',
            json=self.auth_data,
        ).json()['token']

    def __call__(self, request):
        """
        Called for each request using the auth instance.
        """

        # Cache the auth token for subsequent requests using the same auth instance.
        if not self.token:
            self.token = self._fetch_token()

        # Set the request's auth header to 'Bearer <token>', ascii encoded.
        request.headers.update({'Authorization': 'Bearer %s' % self.token.encode('ascii')})

        return request
