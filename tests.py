# coding: utf-8

try:
    from Cookie import SimpleCookie
except:
    from http.cookies import SimpleCookie


from mock import patch, Mock

from tornado import ioloop
from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.escape import native_str
from tornado.web import Application
from tornado.httputil import HTTPHeaders, urlencode

import efq
import ui


TEST_APP_SETTINGS = {
    'cookie_secret': 'cookie_secret',
    'template_path': 'templates',
    'static_path': 'static',
    'ui_modules': ui,
    'debug': True,
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

    def get_app(self):
        return Application(efq.HANDLERS, **TEST_APP_SETTINGS)

    def fetch(self, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = HTTPHeaders()
        h = kwargs['headers']
        if kwargs.pop('eve_trust', True):
            char = kwargs.pop('char', TESTCHAR1)
            if char is not None:
                h.update(get_eve_headers(char))
        else:
            h.add('Eve_trusted', 'No')
        return super(BaseTestCase, self).fetch(*args, **kwargs)


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
    mock = patch('efq.LoginHandler.generate_token', side_effect=side_effect)
    return mock


class TestAccess(BaseTestCase):

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
            s = '''<tr onMouseOver="this.className='trm'" onMouseOut="this.className=''"><td class="logTD" style="white-space:nowrap; max-width:240px;">[<a href="/quote/186508084">i</a>]<a href="/talk/186508084" style="color:#AEE4FF;">2014.01.21 07:20:00</a><font color="#C8FFC8"> +12s</font>&nbsp;</td><td class="logTD" style="white-space:nowrap; max-width:240px;"><a href="/RAISA_Shield" style="color:#CF6">RAISA Shield</a>&nbsp;</td><td class="logTD">&lt;<a href="/RAISA_Shield/p/%s" style="color:#FC3;">%s</a>&gt; %s </td></tr>''' % (TESTCHAR1.name.replace(' ', '_'), TESTCHAR1.name, channel_auth_token)
            mock.side_effect = lambda callback: callback(Mock(body=s))
            headers = HTTPHeaders()
            headers.add('Cookie', cookies['key'].OutputString())
            response = self.fetch('/login/channel_auth', body='', method='POST',
                                  headers=get_cookie_headers(cookies), follow_redirects=False)

        self.assertEqual(response.code, 302)
        self.assertEqual(response.headers['location'], '/login/success')

        response = self.fetch('/login/success',
                              headers=get_cookie_headers(get_cookies(response)))
        self.assertEqual(response.code, 200)
        self.assertIn(TESTCHAR1.name, native_str(response.body))

    @patch('efq.BaseHandler.ONLINE', set([TESTCHAR1]))
    @patch('efq.BaseHandler.FCS', [TESTCHAR1])
    @gen_test
    def test_mail_auth(self):
        response = self.fetch('/login')
        self.assertIn('"/login/mail_auth"', native_str(response.body))

        with faketoken() as mock:

            def cb(data):
                self.assertEqual(data, {
                    'mail_auth_request': {
                        'token': mock.side_effect.token,
                        'character': TESTCHAR2.name,
                        'charid': TESTCHAR2.charid,
                    }
                })

            TESTCHAR1.callbacks.append(cb)

            response = self.fetch("/login/mail_auth", method='POST',
                                  follow_redirects=False, body='', char=TESTCHAR2)

        self.assertEqual(response.code, 302)
        self.assertEqual(
            response.headers['location'],
            '/login?' + urlencode({'mail_auth': 'asked', 'fc': TESTCHAR1.name})
        )

        self.assertEqual(TESTCHAR1.callbacks, [])
