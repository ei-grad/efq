# coding: utf-8

import Cookie

from mock import patch, Mock

from tornado.testing import AsyncHTTPTestCase, gen_test
from tornado.escape import native_str
from tornado.web import Application
from tornado.httputil import HTTPHeaders

import efq
import ui


TEST_APP_SETTINGS = {
    'cookie_secret': 'cookie_secret',
    'template_path': 'templates',
    'static_path': 'static',
    'ui_modules': ui,
    'debug': True,
}

TEST_CHARNAME = 'test 1'
TEST_CHAR = efq.Character(TEST_CHARNAME)
efq.CHARACTERS[TEST_CHARNAME] = TEST_CHAR
TEST_CHARID = '111111111111'
TEST_TOKEN = '0000000000000000'


class BaseTestCase(AsyncHTTPTestCase):

    def get_app(self):
        return Application(efq.HANDLERS, **TEST_APP_SETTINGS)

    def fetch(self, *args, **kwargs):
        if 'headers' not in kwargs:
            kwargs['headers'] = HTTPHeaders()
        h = kwargs['headers']
        if kwargs.pop('eve_trust', True):
            h.add('Eve_trusted', 'Yes')
            h.add('Eve_charname', TEST_CHARNAME)
            h.add('Eve_charid', TEST_CHARID)
        else:
            h.add('Eve_trusted', 'No')
        return super(BaseTestCase, self).fetch(*args, **kwargs)


def get_cookies(resp):
    cookies = Cookie.SimpleCookie()
    for i in resp.headers.get_list('Set-Cookie'):
        cookies.load(native_str(i))
    return cookies


def get_cookie_headers(cookies):
    headers = HTTPHeaders()
    headers.add('Cookie', '; '.join(
        i.OutputString([]) for i in cookies.values() if i.value
    ))
    return headers


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

    def get_login_response(self):
        with patch('efq.LoginHandler.generate_token') as mock:
            mock.return_value = TEST_TOKEN
            return self.fetch('/login')

    @gen_test
    def test_channel_auth(self):
        response = self.get_login_response()
        self.assertIn(TEST_TOKEN, response.body)
        self.assertIn('/login/channel_auth', response.body)
        self.assertIn('Set-Cookie', response.headers)
        cookies = get_cookies(response)
        self.assertIn('key', cookies)

        with patch('efq.ChannelAuthHandler.get_chat_logs') as mock:
            s = '''<tr onMouseOver="this.className='trm'" onMouseOut="this.className=''"><td class="logTD" style="white-space:nowrap; max-width:240px;">[<a href="/quote/186508084">i</a>]<a href="/talk/186508084" style="color:#AEE4FF;">2014.01.21 07:20:00</a><font color="#C8FFC8"> +12s</font>&nbsp;</td><td class="logTD" style="white-space:nowrap; max-width:240px;"><a href="/RAISA_Shield" style="color:#CF6">RAISA Shield</a>&nbsp;</td><td class="logTD">&lt;<a href="/RAISA_Shield/p/%s" style="color:#FC3;">%s</a>&gt; %s </td></tr>''' % (TEST_CHARNAME.replace(' ', '_'), TEST_CHARNAME, TEST_TOKEN)
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
        self.assertIn(TEST_CHARNAME, response.body)

    @patch('efq.BaseHandler.ONLINE', set([TEST_CHAR]))
    @patch('efq.BaseHandler.FCS', [TEST_CHAR])
    @gen_test
    def test_mail_auth(self):
        login_response = self.get_login_response()
        self.assertIn('/login/mail_auth', login_response.body)
