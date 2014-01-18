#!/usr/bin/env python
# coding: utf-8

from functools import wraps
import re, os, binascii
from json import dumps, loads

from tornado import gen, ioloop, web, httpclient, stack_context
from tornado.httputil import urlencode

FLEETS = {
    'Mia Cloks': {
        'fc': 'Mia Cloks',
        'solar_system': 'Qwe',
        'ts_channel': 'Asd',
        'level': 'Vanguard (10)',
        'queue': ['Zwo Zateki'],
    },
}

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
        if 'session' not in kwargs:
            kwargs['session'] = self.session
        return super(BaseHandler, self).render(*args, **kwargs)

    def finish(self, *args, **kwargs):
        if self.session != self.untouched_session:
            self.set_secure_cookie('session', dumps(self.session))
        return super(BaseHandler, self).finish(*args, **kwargs)


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
            self.redirect('/fc')
        elif 'fleet' in self.session:
            if self.session['fleet'] in FLEETS and self.character in FLEETS[self.session['fleet']]['queue']:
                self.redirect('/queue')
            else:
                del self.session['fleet']
                self.render('fleets.html', fleets=get_fleets_list())
        else:
            self.render('fleets.html', fleets=get_fleets_list())

    def post(self):
        FLEETS[self.character] = {
            'fc': self.character,
            'ts_channel': self.get_argument('ts_channel'),
            'level': self.get_argument('level'),
            'solar_system': self.get_argument('solar_system') or u'система неизвестна',
            'queue': [],
        }
        self.redirect('/fc')


class JoinHandler(BaseHandler):
    def post(self):
        if 'fleet' not in self.session:
            fc = self.get_argument('fc')
            if fc in FLEETS:
                queue = FLEETS[fc]['queue']
                if self.character in queue:
                    queue.remove(self.character)
                queue.append(self.character)
                self.session['fleet'] = fc
                self.redirect('/queue')
            else:
                self.send_error(400, u'Этого флота уже нет!')
        else:
            self.send_error(400, u'Вы уже в очереди!')


def fleet_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if 'fleet' not in self.session:
            self.redirect('/')
        elif self.session['fleet'] not in FLEETS or self.character not in FLEETS[self.session['fleet']]['queue']:
            del self.session['fleet']
            self.redirect('/')
        else:
            return func(self, *args, **kwargs)
    return wrapper


class LeaveHandler(BaseHandler):
    @fleet_required
    def post(self):
        if 'fleet' in self.session:
            if self.session['fleet'] in FLEETS:
                queue = FLEETS[self.session['fleet']]['queue']
                if self.character in queue:
                    queue.remove(self.character)
            del self.session['fleet']
        self.redirect('/')


class QueueHandler(BaseHandler):
    @fleet_required
    def get(self, **kwargs):
        fleet = FLEETS[self.session['fleet']]
        queue = fleet['queue']
        self.render('queue.html',
                    fleet=fleet,
                    count=len(queue),
                    position=queue.index(self.character) + 1,
                    **kwargs)


class FCHandler(BaseHandler):

    def get(self):
        if self.character in FLEETS:
            self.render('fc.html', fleet=FLEETS[self.character])
        else:
            self.redirect('/')

    def post(self):
        if self.character in FLEETS:
            FLEETS[self.character].update({
                'ts_channel': self.get_argument('ts_channel'),
                'level': self.get_argument('level'),
                'solar_system': self.get_argument('solar_system'),
            })
            self.get()
        else:
            self.send_error(400)


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
            return self.redirect('/')
        self.render('admin.html')


class DismissHandler(BaseHandler):
    def post(self):
        if self.character in FLEETS:
            del FLEETS[self.character]


CALLBACKS = {}


class PollHandler(BaseHandler):
    @web.asynchronous
    def get(self):
        if self.character not in CALLBACKS:
            CALLBACKS[self.character] = []
        CALLBACKS[self.character].append(stack_context.wrap(self.finish))


class CharacterIDHandler(web.RequestHandler):

    CHARACTERS = {}

    @gen.coroutine
    def get(self):
        character = self.get_argument('name')
        if character not in self.CHARACTERS:
            url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
            url = '?'.join([url, urlencode({'names': character})])
            print(url)
            response = yield httpclient.AsyncHTTPClient().fetch(url)
            print(response.body)
            m = re.search(r'characterID="(\d+)"', response.body.decode('utf-8'))
            if m is not None:
                char_id = m.group(1)
                self.CHARACTERS[character] = char_id
            else:
                return self.send_error(400)
        else:
            char_id = self.CHARACTERS[character]
        self.finish(char_id)


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)

import ui

application = web.Application(
    [
        (r"/", FleetsHandler),
        (r"/login", IdentifyHandler),
        (r"/queue", QueueHandler),
        (r"/join", JoinHandler),
        (r"/leave", LeaveHandler),
        (r"/dismiss", DismissHandler),
        (r"/fc", FCHandler),
        (r"/admin", AdminHandler),
        (r"/poll", PollHandler),
        (r"/char_id", CharacterIDHandler),
    ],
    cookie_secret=cookie_secret,
    template_path='templates',
    static_path='static',
    ui_modules=ui,
    debug=True,
)


if __name__ == "__main__":
    application.listen(8888)
    ioloop.IOLoop.instance().start()
