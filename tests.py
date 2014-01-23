# coding: utf-8

try:
    from Cookie import SimpleCookie
except:
    from http.cookies import SimpleCookie

from datetime import timedelta
import random
import subprocess

from mock import patch, Mock

from tornado import iostream
from tornado.ioloop import IOLoop
from tornado.testing import AsyncHTTPTestCase, gen_test, get_async_test_timeout
from tornado.escape import native_str
from tornado.web import Application, create_signed_value
from tornado.httputil import HTTPHeaders, urlencode
from tornado.httpclient import AsyncHTTPClient

import efq
import ui


TEST_APP_SETTINGS = {
    'cookie_secret': 'cookie_secret',
    'template_path': 'templates',
    'static_path': 'static',
    'ui_modules': ui,
    'debug': False,
}


try:
    _char_ids = iter(xrange(1000000001, 2000000000))
except:
    _char_ids = iter(range(1000000001, 2000000000))


def get_test_char(name):
    char = efq.Character(name)
    char.charid = str(next(_char_ids))
    efq.CHARACTERS[name] = char
    return char


def get_eve_headers(char):
    return {
        'Eve_trusted': 'Yes',
        'Eve_charname': char.name,
        'Eve_charid': char.charid,
    }


TESTCHAR1 = get_test_char('test 1')
TESTCHAR2 = get_test_char('test 2')


class BaseTestCase(AsyncHTTPTestCase):

    logged_in = True

    def setUp(self):
        super(BaseTestCase, self).setUp()
        port = random.randint(1024, 65535)
        self.redis_popen = subprocess.Popen(['redis-server', '--bind', 'localhost', '--port', str(port), '--maxclients', '1000'], stdout=subprocess.PIPE)
        stream = iostream.PipeIOStream(self.redis_popen.stdout.fileno())
        redis_not_started = True
        def check_redis():
            if redis_not_started:
                raise Exception('Redis not started!')
        self.io_loop.add_timeout(timedelta(seconds=1), check_redis)
        stream.read_until(('The server is now ready to accept connections on port %d' % port).encode('ascii'), self.stop)
        self.wait()
        redis_not_started = False
        assert self.http_server.io_loop == self.io_loop
        assert self.io_loop == IOLoop.current()

        from toredis import Redis
        self.redis_patch = patch('efq.redis', Redis(port=port))
        self.redis_patch.start()

    def tearDown(self):
        super(BaseTestCase, self).tearDown()
        self.redis_popen.kill()
        self.redis_patch.stop()

    def get_http_client(self):
        return AsyncHTTPClient(io_loop=self.io_loop, defaults={
            'connect_timeout': get_async_test_timeout(),
            'request_timeout': get_async_test_timeout(),
        })

    def get_app(self):
        return Application(efq.HANDLERS, **TEST_APP_SETTINGS)

    def get_new_ioloop(self):
        IOLoop._instance = IOLoop()
        return IOLoop.instance()

    def fetch(self, *args, **kwargs):
        kwargs['headers'] = self.get_headers(
            headers=kwargs.get('headers'),
            char=kwargs.pop('char', TESTCHAR1),
            eve_trust=kwargs.pop('eve_trust', True),
            logged_in=kwargs.pop('logged_in', self.logged_in)
        )
        return super(BaseTestCase, self).fetch(*args, **kwargs)

    def get_headers(self, headers=None, char=TESTCHAR1, eve_trust=True, logged_in=None):
        if headers is None:
            headers = HTTPHeaders()
        if eve_trust:
            if char is not None:
                headers.update(get_eve_headers(char))
        else:
            headers.add('Eve_trusted', 'No')
        if logged_in is None: logged_in = self.logged_in
        if char is not None and logged_in:
            if 'Cookie' in headers:
                cookies = headers.pop('Cookie').split('; ')
            else:
                cookies = []
            headers.add('Cookie', '; '.join(cookies + [
                'character=%s' % create_signed_value(
                    TEST_APP_SETTINGS['cookie_secret'], 'character', char.name
                ),
                'uuid=%s' % create_signed_value(
                    TEST_APP_SETTINGS['cookie_secret'], 'uuid', efq.BaseHandler.uuid
                )
            ]))
        return headers

    def assertIsRedirect(self, response, location, code=302):
        self.assertEqual(response.code, code)
        self.assertEqual(response.headers['location'], location)

    def assertRespContains(self, response, s, code=200):
        if response.error:
            raise response.error
        self.assertEqual(response.code, code)
        self.assertIn(s, native_str(response.body))


def get_cookies(resp):
    cookies = SimpleCookie()
    for i in resp.headers.get_list('Set-Cookie'):
        cookies.load(native_str(i))
    return cookies


def get_cookie_headers(cookies):
    headers = HTTPHeaders()
    headers.add('Cookie', '; '.join(
        i.OutputString([]) for i in cookies.values() if i.value
    ))
    return headers


def faketoken():
    def side_effect(x):
        side_effect.token = native_str('0' * x * 2)
        return side_effect.token
    side_effect.token = None
    mock = patch('efq.BaseLoginHandler.generate_token', side_effect=side_effect)
    return mock


EVELIVE_LINE = ('''<tr onMouseOver="this.className='trm'" onMouseOut="this.'''
'''className=''"><td class="logTD" style="white-space:nowrap; max-width:240'''
'''px;">[<a href="/quote/186508084">i</a>]<a href="/talk/186508084" style="'''
'''color:#AEE4FF;">2014.01.21 07:20:00</a><font color="#C8FFC8"> +12s</font'''
'''>&nbsp;</td><td class="logTD" style="white-space:nowrap; max-width:240px'''
''';"><a href="/RAISA_Shield" style="color:#CF6">RAISA Shield</a>&nbsp;</td'''
'''><td class="logTD">&lt;<a href="/RAISA_Shield/p/%s" style="color:#FC3;">'''
'''%s</a>&gt; %s </td></tr>''')


class TestAccess(BaseTestCase):

    logged_in = False

    @gen_test
    def test_trust(self):
        resp = self.fetch('/login', follow_redirects=False)
        self.assertEqual(resp.code, 200)

    @gen_test
    def test_no_trust(self):
        resp = self.fetch('/login', eve_trust=False)
        self.assertEqual(resp.code, 200)
        self.assertEqual(resp.effective_url, self.get_url('/trust'))

    @gen_test
    def test_channel_auth(self):

        with faketoken() as mock:
            response = self.fetch('/login')
            channel_auth_token = mock.side_effect.token

        self.assertIn(channel_auth_token, native_str(response.body))
        self.assertIn('"/login/channel_auth"', native_str(response.body))
        self.assertIn('Set-Cookie', response.headers)
        cookies = get_cookies(response)
        self.assertIn('key', cookies)

        with patch('efq.ChannelAuthHandler.get_chat_logs') as mock:
            s = EVELIVE_LINE % (TESTCHAR1.name.replace(' ', '_'), TESTCHAR1.name, channel_auth_token)
            mock.side_effect = lambda callback: callback(Mock(body=s))
            headers = HTTPHeaders()
            headers.add('Cookie', cookies['key'].OutputString())
            response = self.fetch('/login/channel_auth',
                                  method='POST', body='',
                                  headers=get_cookie_headers(cookies),
                                  follow_redirects=False)

            self.assertIsRedirect(response, '/login/success')

        response = self.fetch('/login/success', headers=get_cookie_headers(get_cookies(response)))
        self.assertRespContains(response, TESTCHAR1.name)

    @patch('efq.BaseHandler.FCS', [TESTCHAR2])
    @patch('efq.BaseHandler.ONLINE', set([TESTCHAR2]))
    @gen_test
    def test_mail_auth(self):
        response = self.fetch('/login')
        self.assertRespContains(response, 'action="/login/mail_auth"')

        poll_cb = Mock()
        TESTCHAR2.callbacks.append(poll_cb)

        with faketoken() as mock:
            response = self.fetch("/login/mail_auth", method='POST',
                                  follow_redirects=False, body='')
            self.assertIsRedirect(response, '/login?' + urlencode({
                'mail_auth': 'asked',
                'fc': TESTCHAR2.name,
            }))
            event = {
                'mail_auth_request': {
                    'token': mock.side_effect.token,
                    'character': TESTCHAR1.name,
                    'charid': TESTCHAR1.charid,
                }
            }
            poll_cb.assert_called_once_with(event)
            self.assertIsNotNone(mock.side_effect.token)
            self.assertIsRedirect(
                self.fetch("/login/token/%s" % mock.side_effect.token, follow_redirects=False),
                '/login/success'
            )


# vim: set tw=0:
