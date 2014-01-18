#!/usr/bin/env python
# coding: utf-8

from functools import wraps
import re, os, binascii
from json import dumps, loads

from tornado import gen, ioloop, web, httpclient


FLEETS = {}
ADMINS = [
    'Mia Cloks',
    'Grim Altero',
    'Zwo Zateki',
]


class BaseHandler(web.RequestHandler):

    def prepare(self):
        super(BaseHandler, self).prepare()
        session = self.get_secure_cookie('session', None)
        if session is None:
            key = binascii.b2a_hex(os.urandom(8)).decode('ascii')
            self.session = {
                'key': 'EFQKEY_%s' % key.upper(),
            }
            self.untouched_session = {}
        else:
            session = session.decode('utf-8')
            self.session = loads(session)
            self.untouched_session = loads(session)
        self.character = self.session.get('character', None)

    def render(self, *args, **kwargs):
        if self.session != self.untouched_session:
            self.set_secure_cookie('session', dumps(self.session))
        if 'session' not in kwargs:
            kwargs['session'] = self.session
        return super(BaseHandler, self).render(*args, **kwargs)


def get_identified_character(content, key):
    return re.search('>([^<>]*)</a>&gt; *%s *' % key, content).group(1)


class IdentifyHandler(BaseHandler):

    def get(self):
        if 'key' in self.session:
            self.render('identify.html')
        else:
            self.render('already_identified.html')

    @gen.coroutine
    def post(self):
        if 'key' in self.session:
            response = yield httpclient.AsyncHTTPClient().fetch("http://eve-live.com/RAISA_Shield")
            if response.code != 200:
                error = u'Не удалось проверить сообщения. Попробуйте ещё раз.'
                self.render('error.html', error=error)
            elif self.session['key'] in response.body.decode('utf-8'):
                self.session['character'] = get_identified_character(
                    response.body.decode('utf-8'), self.session.pop('key')
                )
                self.render("identified.html")
            else:
                self.render("identification_failed.html")


def get_fleets_list():
    return sorted(FLEETS.values(),
                  key=lambda x: '%s:%s' % (x['level'], x['solar_system']))


class FleetsHandler(BaseHandler):

    def get(self):
        if self.character in FLEETS:
            self.render_fc()
        elif 'fleet' in self.session:
            if self.session['fleet'] in FLEETS and self.character in FLEETS[self.session['fleet']]:
                self.render_queue()
            else:
                del self.session['fleet']
                self.render_fleets(msg='Вы уже не в очереди!')
        else:
            self.render_fleets()

    def post(self):
        action = self.get_argument('action')
        if action == 'new':
            FLEETS[self.character] = {
                'fc': self.character,
                'ts_channel': self.get_argument('ts_channel'),
                'level': self.get_argument('level'),
                'solar_system': self.get_argument('solar_system') or u'система неизвестна',
                'queue': [],
            }
            return self.render_fc()
        elif action == 'save':
            FLEETS[self.character].update({
                'ts_channel': self.get_argument('ts_channel'),
                'level': self.get_argument('level'),
                'solar_system': self.get_argument('solar_system'),
            })
            return self.render_fc()
        elif action == 'join':
            if 'fleet' not in self.session:
                fc = self.get_argument('fc')
                if fc in FLEETS:
                    queue = FLEETS[fc]['queue']
                    if self.character in queue:
                        queue.remove(self.character)
                    queue.append(self.character)
                    self.session['fleet'] = fc
                    return self.render_queue()
            else:
                return self.render_queue(error=u'Вы уже в очереди!')
        elif action == 'leave':
            if 'fleet' in self.session:
                if self.session['fleet'] in FLEETS:
                    queue = FLEETS[self.session['fleet']]['queue']
                    if self.character in queue:
                        queue.remove(self.character)
                del self.session['fleet']
        return self.render_fleets()

    def render_fleets(self, **kwargs):
        self.render('fleets.html', fleets=get_fleets_list(), **kwargs)

    def render_queue(self, **kwargs):
        fleet = FLEETS[self.session['fleet']]
        self.render('queue.html',
                    fleet=fleet,
                    count=len(fleet['queue']),
                    position=fleet['queue'].index(self.character),
                    **kwargs)

    def render_fc(self, **kwargs):
        self.render('fc.html', fleet=FLEETS[self.character], **kwargs)


def admin_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        return func(self, *args, **kwargs)
        if self.character in ADMINS:
            return func(self, *args, **kwargs)
        else:
            self.send_error(403)
    return wrapper


class AdminHandler(BaseHandler):

    @admin_required
    def get(self):
        self.render('admin.html')

    @admin_required
    def post(self):
        action = self.get_argument('action')
        if action == 'fake_character':
            self.session['character'] = self.get_argument('character')
        self.render('admin.html')


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


application = web.Application(
    [
        (r"/", FleetsHandler),
        (r"/login", IdentifyHandler),
        (r"/admin", AdminHandler),
    ],
    cookie_secret=cookie_secret,
    template_path='templates',
    static_path='static',
    debug=True,
)


if __name__ == "__main__":
    application.listen(8888)
    ioloop.IOLoop.instance().start()
