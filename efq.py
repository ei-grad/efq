#!/usr/bin/env python
# coding: utf-8

import logging
from functools import wraps
import re
import os
import binascii

from tornado import gen, ioloop, web, httpclient, stack_context
from tornado.options import options, define, parse_command_line
from tornado.httputil import urlencode


logger = logging.getLogger(__name__)

TITLE = 'EVE Online Fleet Queue'

ADMINS = [
    u'Mia Cloks',
    u'Grim Altero',
    u'Zwo Zateki',
]


CHARACTERS = {}


def get_character(name, *args, **kwargs):
    if name not in CHARACTERS:
        CHARACTERS[name] = Character(name, *args, **kwargs)
    return CHARACTERS[name]


FLEETS = {}


def get_fleet(fc, *args, **kwargs):
    if fc not in FLEETS:
        FLEETS[fc] = Fleet(fc, *args, **kwargs)
    return FLEETS[fc]


class Character(object):

    def __init__(self, name):
        logger.debug('Created character %s', name)
        self.name = name
        self.fleet = None
        self.is_fc = False
        self.is_admin = name in ADMINS
        self.callbacks = []

    def refresh(self):
        callbacks, self.callbacks = self.callbacks, []
        for callback in callbacks:
            ioloop.IOLoop.instance().add_callback(callback)


class Fleet(object):

    def __init__(self, fc, solar_system=None, ts_channel=None, level=None):
        self._fc = fc
        self.fcs = [fc]
        fc.fleet = self
        fc.is_fc = True
        self.solar_system = solar_system
        self.ts_channel = ts_channel
        self.level = level
        self.queue = []

    @property
    def fc(self):
        return self._fc

    def enqueue(self, character):
        if character in self.queue:
            self.queue.remove(character)
        self.queue.append(character)
        character.fleet = self
        character.is_fc = False
        for fc in self.fcs:
            fc.refresh()
        character.refresh()

    def dequeue(self, character):
        if character in self.queue:
            self.queue.remove(character)
        for fc in self.fcs:
            fc.refresh()
        character.fleet = None
        character.refresh()

    def dismiss(self, new_fc=None):
        del FLEETS[self.fc]
        queue = self.queue
        fcs = self.fcs
        fcs.remove(self.fc)

        self.fc.fleet = None
        self.fc.is_fc = False

        if new_fc is None:
            for fc in self.fcs:
                if fc.callbacks:
                    new_fc = fc
                    break

        if new_fc is not None:
            new_fleet = get_fleet(
                new_fc, self.solar_system, self.ts_channel, self.level
            )
            new_fleet.queue = self.queue
            new_fleet.fcs = self.fcs
        else:
            new_fleet = None
            for fc in fcs:
                fc.is_fc = False

        self.fc.refresh()
        for fc in fcs:
            fc.fleet = new_fleet
            fc.refresh()
        for character in queue:
            character.fleet = new_fleet
            character.refresh()


class BaseHandler(web.RequestHandler):

    login_required = True

    def prepare(self):
        super(BaseHandler, self).prepare()
        self.character = self.get_secure_cookie('character', None)
        if self.character is not None:
            self.character = get_character(self.character.decode('utf-8'))
        if self.character is None and self.login_required:
            self.redirect('/login')

    def render(self, *args, **kwargs):
        kwargs.update({
            'TITLE': TITLE,
            'character': self.character,
        })
        return super(BaseHandler, self).render(*args, **kwargs)


def get_identified_character(content, key):
    return re.search('>([^<>]*)</a>&gt; *%s *' % key, content).group(1)


class IdentifyHandler(BaseHandler):

    login_required = False

    def get(self):
        if self.character is not None:
            self.render('already_identified.html')
        else:
            key = self.get_secure_cookie('key', None)
            if key is None:
                key = binascii.b2a_hex(os.urandom(8)).decode('ascii')
                self.set_secure_cookie('key', key)
            self.render('identify.html', key=key)

    @gen.coroutine
    def post(self):
        key = self.get_secure_cookie('key', None)
        if key is not None:
            response = yield httpclient.AsyncHTTPClient().fetch(
                "http://eve-live.com/RAISA_Shield"
            )
            content = response.body.decode('utf-8')
            if key in content:
                character = get_identified_character(content, key)
                self.clear_cookie('key')
                self.set_secure_cookie('character', character.encode('utf-8'))
                self.render("identified.html")
            else:
                self.render("identification_failed.html", key=key)
        else:
            self.get()


def get_fleets_list():
    return sorted(FLEETS.values(),
                  key=lambda x: '%s:%s' % (x.level, x.solar_system))


def free_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.character.fleet is not None:
            if self.character.is_fc is True:
                self.redirect('/fc')
            else:
                self.redirect('/queue')
        else:
            return func(self, *args, **kwargs)
    return wrapper


def queue_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.character.fleet is None:
            self.redirect('/')
        elif self.character.is_fc is True:
            self.redirect('/fc')
        else:
            return func(self, *args, **kwargs)
    return wrapper


def fc_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if self.character.fleet is None:
            self.redirect('/')
        elif self.character.is_fc is False:
            self.redirect('/queue')
        else:
            return func(self, *args, **kwargs)
    return wrapper


class FleetsHandler(BaseHandler):

    @free_required
    def get(self):
        self.render('fleets.html', fleets=get_fleets_list())

    @free_required
    def post(self):
        get_fleet(self.character,
                  self.get_argument('solar_system') or u'система выбирается',
                  self.get_argument('ts_channel'),
                  self.get_argument('level'))
        self.redirect('/fc')


class JoinHandler(BaseHandler):
    @free_required
    def post(self):
        fleet = get_character(self.get_argument('fc')).fleet
        if fleet is not None:
            if self.character in fleet.queue:
                fleet.dequeue(self.character)
            fleet.enqueue(self.character)
            self.redirect('/queue')
        else:
            self.redirect('/')


class LeaveHandler(BaseHandler):
    @queue_required
    def post(self):
        self.character.fleet.dequeue(self.character)
        self.redirect('/')


class QueueHandler(BaseHandler):
    @queue_required
    def get(self):
        self.render('queue.html',
                    fleet=self.character.fleet,
                    queue=self.character.fleet.queue)


class FCHandler(BaseHandler):
    @fc_required
    def get(self):
        self.render('fc.html', fleet=self.character.fleet)


class SaveHandler(BaseHandler):
    @fc_required
    def post(self):
        fleet = self.character.fleet
        fleet.ts_channel = self.get_argument('ts_channel')
        fleet.level = self.get_argument('level')
        fleet.solar_system = self.get_argument('solar_system')
        self.redirect('/fc')


def admin_required(func):
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        if options.devel:
            return func(self, *args, **kwargs)
        else:
            if self.character.name in ADMINS:
                return func(self, *args, **kwargs)
            else:
                self.send_error(403)
    return wrapper


class AdminHandler(BaseHandler):

    login_required = False

    @admin_required
    def get(self):
        self.render('admin.html')

    @admin_required
    def post(self):
        action = self.get_argument('action')
        if action == 'fake_character':
            self.set_secure_cookie('character', self.get_argument('character'))
            self.clear_cookie('key')
            return self.redirect('/')
        else:
            self.send_error(400)


class DismissHandler(BaseHandler):
    @fc_required
    def post(self):
        self.character.fleet.dismiss()
        self.redirect('/')


class PopHandler(BaseHandler):
    @fc_required
    def post(self):
        character = get_character(self.get_argument('character'))
        self.character.fleet.dequeue(character)


CALLBACKS = {}


class PollHandler(BaseHandler):
    @web.asynchronous
    def get(self):
        if self.character is not None:
            self.cb = stack_context.wrap(self.finish)
            self.character.callbacks.append(self.cb)
        else:
            self.finish()

    def on_connection_close(self):
        if self.cb in self.character.callbacks:
            self.character.callbacks.remove(self.cb)


class CharacterIDHandler(web.RequestHandler):

    CHARACTERS = {}

    @gen.coroutine
    def get(self):
        character = self.get_argument('name')
        if character not in self.CHARACTERS:
            url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
            url = '?'.join([url, urlencode({'names': character})])
            response = yield httpclient.AsyncHTTPClient().fetch(url)
            content = response.body.decode('utf-8')
            m = re.search(r'characterID="(\d+)"', content)
            if m is not None:
                self.CHARACTERS[character] = m.group(1)
                self.finish(self.CHARACTERS[character])
            else:
                self.send_error(400)
        else:
            self.finish(self.CHARACTERS[character])


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


if __name__ == "__main__":

    import ui

    application = web.Application(
        [
            (r"/", FleetsHandler),
            (r"/login", IdentifyHandler),
            (r"/queue", QueueHandler),
            (r"/join", JoinHandler),
            (r"/leave", LeaveHandler),
            (r"/fc", FCHandler),
            (r"/save", SaveHandler),
            (r"/pop", PopHandler),
            (r"/dismiss", DismissHandler),
            (r"/admin", AdminHandler),
            (r"/poll", PollHandler),
            (r"/char_id", CharacterIDHandler),
        ],
        cookie_secret=cookie_secret,
        template_path='templates',
        static_path='static',
        ui_modules=ui,
        debug=options.devel,
        xsrf_token=True,
    )

    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)

    parse_command_line()

    application.listen(options.port, options.host)

    if options.devel:
        get_fleet(
            get_character(u'Mia Cloks'),
            'Vilur',
            'Shield-Флот 1',
            'HQ (40)'
        ).enqueue(get_character(u'Zwo Zateki'))

    ioloop.IOLoop.instance().start()
