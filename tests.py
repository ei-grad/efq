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
from tornado.testing import AsyncHTTPTestCase, gen_test, get_async_test_timeout, ExpectLog
from tornado.escape import native_str
from tornado.web import Application, create_signed_value
from tornado.httputil import HTTPHeaders, urlencode
from tornado.httpclient import AsyncHTTPClient
from tornado.concurrent import Future

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


def get_test_char(name, charid=None, fit=None):
    char = efq.Character(name)
    char.charid = str(next(_char_ids)) if charid is None else charid
    char.fit = fit
    efq.CHARACTERS[name] = char
    return char


def get_eve_headers(char):
    return {
        'Eve_trusted': 'Yes',
        'Eve_charname': char.name,
        'Eve_charid': char.charid,
    }


VINDI_FIT = ('17740:2048;1:26404;1:2281;2:26442;1:10190;4:1999;2:26448;1:3186;8'
             ':19359;1:14268;1:19231;1:29009;1:29011;1:28999;1:21740;8269:29001;1::')

BASI_FIT = ('11985:2048;1:31366;1:16487;2:1355;1:1964;1:18672;1:2456;5:31796;1'
            ':3608;4:31932;1:4349;1:19231;1::')


class BaseTestCase(AsyncHTTPTestCase):

    logged_in = True
    fake_redis = False

    def setUp(self):

        super(BaseTestCase, self).setUp()

        if self.fake_redis:
            port = random.randint(1024, 65535)
            self._redis_popen = subprocess.Popen(['redis-server', '--bind', 'localhost', '--port', str(port), '--maxclients', '1000'], stdout=subprocess.PIPE)
            stream = iostream.PipeIOStream(self._redis_popen.stdout.fileno())
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
            self._redis_patch = patch('efq.redis', Redis(port=port))
            self._redis_patch.start()

        efq.CHARACTERS = {}
        self.testchar1 = get_test_char('test 1', '1000000001', VINDI_FIT)
        self.testchar2 = get_test_char('test 2', '1000000002', BASI_FIT)

    def tearDown(self):
        super(BaseTestCase, self).tearDown()
        if self.fake_redis:
            self._redis_popen.kill()
            self._redis_patch.stop()

    def httpclient_patch(self, code, body):
        future = Future()
        future.set_result(Mock(code=code, body=body))
        return patch('tornado.httpclient.AsyncHTTPClient.fetch', return_value=future)

    def redis_patch(self, value):
        future = Future()
        future.set_result(value)
        return patch('toredis.Redis.get', return_value=future)

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
            char=kwargs.pop('char', self.testchar1),
            eve_trust=kwargs.pop('eve_trust', True),
            logged_in=kwargs.pop('logged_in', self.logged_in)
        )
        if 'follow_redirects' not in kwargs:
            kwargs['follow_redirects'] = False
        return super(BaseTestCase, self).fetch(*args, **kwargs)

    def get_headers(self, headers=None, char=None, eve_trust=True, logged_in=None):
        if headers is None:
            headers = HTTPHeaders()
        if eve_trust:
            if char is not None:
                headers.update(get_eve_headers(char))
        else:
            headers.add('Eve_trusted', 'No')
        if logged_in is None: logged_in = self.logged_in
        if char is None:
            char = self.testchar1
        if logged_in:
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
        if response.code == 599 and response.error:
            raise response.error
        self.assertEqual(response.code, code)
        self.assertIn(s, native_str(response.body))


def get_cookies(response, cookies=None):
    if cookies is None:
        cookies = SimpleCookie()
    for i in response.headers.get_list('Set-Cookie'):
        cookies.load(native_str(i))
    return cookies


def get_cookie_headers(cookies=None, response=None):
    if response is not None:
        cookies = get_cookies(response, cookies)
    if cookies is None:
        return None
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
    fake_redis = True

    def test_trust(self):
        resp = self.fetch('/login')
        self.assertEqual(resp.code, 200)

    # XXX: which page requires trust?
    def disabled_test_no_trust(self):
        resp = self.fetch('/login', eve_trust=False)
        self.assertEqual(resp.code, 200)
        self.assertEqual(resp.effective_url, self.get_url('/trust'))

    def test_channel_auth(self):

        def login(char, cookies=None):

            with faketoken() as mock:
                response = self.fetch('/login', char=char, headers=get_cookie_headers(cookies))
                channel_auth_token = mock.side_effect.token

            cookies = get_cookies(response, cookies)

            self.assertRespContains(response, channel_auth_token)
            self.assertRespContains(response, '"/login/channel_auth"')
            self.assertIn('Set-Cookie', response.headers)
            self.assertIn('key', cookies)

            with patch('efq.ChannelAuthHandler.get_chat_logs') as mock:
                s = EVELIVE_LINE % (char.name.replace(' ', '_'), char.name, channel_auth_token)
                mock.side_effect = lambda callback: callback(Mock(body=s))
                response = self.fetch('/login/channel_auth',
                                      method='POST', body='',
                                      headers=get_cookie_headers(cookies, response),
                                      follow_redirects=False,
                                      char=char)

                self.assertIsRedirect(response, '/login/success')

            response = self.fetch('/login/success', headers=get_cookie_headers(cookies, response), char=char)
            self.assertRespContains(response, char.name)

            return get_cookies(response, cookies)

        cookies = login(self.testchar1)
        login(self.testchar2, cookies)

    def test_mail_auth(self):

        with patch('efq.BaseHandler.FCS', [self.testchar2]):
            with patch('efq.BaseHandler.ONLINE', set([self.testchar2])):

                response = self.fetch('/login')
                self.assertRespContains(response, 'action="/login/mail_auth"')

                poll_cb = Mock()
                self.testchar2.callbacks.append(poll_cb)

                with faketoken() as mock:
                    response = self.fetch("/login/mail_auth", method='POST',
                                          follow_redirects=False, body='')
                    self.assertIsRedirect(response, '/login?' + urlencode({
                        'mail_auth': 'asked',
                        'fc': self.testchar2.name,
                    }))
                    expected_event = {
                        'action': 'mail_auth_request',
                        'token': mock.side_effect.token,
                        'character': self.testchar1.name,
                        'charid': self.testchar1.charid,
                    }
                    poll_cb.assert_called_once_with(expected_event)
                    self.assertIsNotNone(mock.side_effect.token)
                    self.assertIsRedirect(
                        self.fetch("/login/token/%s" % mock.side_effect.token, follow_redirects=False),
                        '/login/success'
                    )


class TestCharacter(BaseTestCase):

    @gen_test
    def test_get_character(self):

        with self.httpclient_patch(200, b'characterID="1111"') as hcp:
            with self.redis_patch('123:123;2::') as rp:
                char = yield efq.get_character('qwe')
                self.assertEqual(char.name, 'qwe')
                self.assertEqual(char.charid, '1111')
                self.assertEqual(char.fit, '123:123;2::')

                char2 = yield efq.get_character('qwe')
                self.assertIs(char, char2)
                hcp.assert_called_once_with('https://api.eveonline.com/eve/CharacterID.xml.aspx?names=qwe')
                rp.assert_called_once_with('efq:fitting:qwe')

        with self.httpclient_patch(200, b'characterID="1112"'):
            with self.redis_patch('') as rp:
                char3 = yield efq.get_character('asd')
                rp.assert_called_once_with('efq:fitting:asd')
                self.assertIsNot(char, char3)
                self.assertIsNone(char3.fit)

    @gen_test
    def test_invalid_character(self):
        with ExpectLog('efq', r"Can't get charid for zxc!"):
            with self.assertRaises(efq.CharacterNotFound):
                with self.httpclient_patch(200, b'characterID="0"'):
                    with self.redis_patch(''):
                        _ = yield efq.get_character('zxc')


    @gen_test
    def test_invalid_response(self):
        with ExpectLog('efq', r"Request https://api.eveonline.com/eve/CharacterID.xml.aspx\?names=zxc failed:"):
            with ExpectLog('efq', r"Can't get charid for zxc!"):
                with self.assertRaises(Exception):
                    with self.httpclient_patch(200, b'blablabla'):
                        with self.redis_patch(''):
                            _ = yield efq.get_character('zxc')

    @gen_test
    def test_redis_exception(self):
        with ExpectLog('efq', "Failed to get fit from redis!"):
            with self.httpclient_patch(200, b'characterID="1111"'):
                with self.redis_patch('') as rp:
                    rp.side_effect = Exception
                    char = yield efq.get_character('zxc')
                    self.assertEqual(char.charid, "1111")

    def test_repr(self):
        self.assertEqual(repr(self.testchar1), '<Character:test 1:1000000001 at %s>' % hex(id(self.testchar1)))

    def test_is_admin(self):
        with patch('efq.BaseHandler.ADMINS', [self.testchar1]):
            self.assertTrue(self.testchar1.is_admin)
            self.assertFalse(self.testchar2.is_admin)

    def test_ship(self):
        self.assertEqual(self.testchar1.ship, 'Vindicator')
        self.assertEqual(self.testchar2.ship, 'Basilisk')
        char = efq.Character('bad')
        self.assertEqual(char.ship, 'Неопределен')
        char.fit = '123123123:1223;1::'
        self.assertEqual(char.ship, 'Неопределен')

    def test_add_message(self):
        self.testchar1.add_message('Message')
        self.testchar1.add_message('Message', 'error')
        self.assertNotEqual(self.testchar1.messages[0][0], self.testchar1.messages[1][0])
        self.testchar1.remove_message(self.testchar1.messages[1][0])
        self.assertEqual(len(self.testchar1.messages), 1)
        self.testchar1.remove_message(self.testchar1.messages[0][0])
        self.assertEqual(len(self.testchar1.messages), 0)

    def test_to_json(self):
        self.assertEqual(self.testchar1.to_json(), {
            'charid': '1000000001',
            'fleet': None,
            'is_admin': False,
            'is_fc': False,
            'name': 'test 1'
        })
        self.assertEqual(self.testchar1.to_json(include_fit=True), {
            'charid': '1000000001',
            'fleet': None,
            'is_admin': False,
            'is_fc': False,
            'name': 'test 1',
            'fit': VINDI_FIT,
        })


class TestFleets(BaseTestCase):

    def setUp(self):
        super(TestFleets, self).setUp()
        self.fleet = efq.Fleet(self.testchar1, fleet_type='Assault (20)')
        self.p = patch('efq.FLEETS', {self.testchar1: self.fleet})
        self.p.start()

    def tearDown(self):
        self.p.stop()

    def test_get_fleet(self):
        self.assertIs(efq.get_fleet(self.testchar1), self.fleet)
        self.assertIsNot(efq.get_fleet(self.testchar2), self.fleet)

    def test_to_json(self):
        self.fleet.enqueue(self.testchar2)
        self.assertEqual(self.fleet.to_json(), {
            'fc': 'test 1',
            'fcs': ['test 1'],
            'fleet_type': 'Assault (20)',
            'queue': ['test 2'],
        })

    def test_fc(self):
        self.assertIs(self.fleet.fc, self.testchar1)

    def test_queue(self):

        self.fleet.enqueue(self.testchar2)
        self.assertIs(self.testchar2.fleet, self.fleet)
        self.assertIn(self.testchar2, self.fleet.queue)
        self.assertFalse(self.testchar2.is_fc)

        char = get_test_char('test 3')
        char.fleet = None
        self.fleet.enqueue(char)
        self.assertEqual(len(self.fleet.queue), 2)
        self.assertIs(self.fleet.queue[0], self.testchar2)
        self.assertIs(self.fleet.queue[1], char)

        self.fleet.enqueue(self.testchar2)
        self.assertEqual(len(self.fleet.queue), 2)
        self.assertIs(self.fleet.queue[0], char)
        self.assertIs(self.fleet.queue[1], self.testchar2)

        with self.assertRaises(efq.CharacterInFleetFCS):
            self.fleet.enqueue(self.testchar1)

        self.fleet.dequeue(char)
        self.assertEqual(len(self.fleet.queue), 1)
        self.assertIsNone(char.fleet)
        self.assertFalse(char.is_fc)

        char.fleet = Mock()
        with self.assertRaises(efq.CharacterInOtherFleet):
            self.fleet.enqueue(char)

    def test_transfer(self):
        pass

# vim: set tw=0:
