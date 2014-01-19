#!/usr/bin/env python
# coding: utf-8

from datetime import timedelta
from functools import wraps
import binascii
import json
import logging
import os
import re

from tornado import gen, ioloop, web, httpclient, stack_context
from tornado.options import options, define, parse_command_line
from tornado.httputil import urlencode

import ui


logger = logging.getLogger(__name__)

TITLE = 'EVE Online Fleet Queue'

FLEET_TYPES = ['Vanguard (10)', 'Assault (20)', 'HQ (40)']
PREFERRED_SHIPS = [
    'Vindicator',
    'Machariel',
    'Nightmar',
    'Basilisk',
    'Scimitar',
    'Vargur,'
    'Loki',
    'Megathron Navy Issue',
    'Bhaalgorn',
    'Tempest Fleet Issue',
    'Rokh',
    'Maelstrom',
    'Hyperion',
    'Golem',
    'Tengu',
    'Tempest',
    'Raven Navy Issue',
    'Rattlesnake',
    'Dominix Navy Issue',
    'Armageddon Navy Issue',
    'Abaddon',
    'Scorpion Navy Issue',
    'Raven',
    'Drake',
    'Apocalypse Navy Issue',

]

ADMINS = [
    u'Mia Cloks',
    u'Grim Altero',
    u'Zwo Zateki',
]


CHARACTERS = {}


@gen.coroutine
def get_character(name):
    if name not in CHARACTERS:
        character = Character(name)
        CHARACTERS[name] = character
        while True:
            url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
            url = '?'.join([url, urlencode({'names': name})])
            response = yield httpclient.AsyncHTTPClient().fetch(url)
            content = response.body.decode('utf-8')
            m = re.search(r'characterID="(\d+)"', content)
            if m is not None:
                character.char_id = m.group(1)
                logger.debug('Got %s char_id: %s', name, character.char_id)
                break
            _ = yield gen.Task(ioloop.IOLoop.instance().add_timeout,
                               timedelta(seconds=5))
    raise gen.Return(CHARACTERS[name])


FLEETS = {}


def get_fleet(fc, fleet_type=None):
    if fc not in FLEETS:
        FLEETS[fc] = Fleet(fc, fleet_type=fleet_type)
    return FLEETS[fc]


class Character(object):

    def __init__(self, name):
        logger.debug('Created character %s', name)
        self.name = name
        self.fleet = None
        self.is_fc = False
        self.is_admin = name in ADMINS
        self.fit = None
        self.callbacks = []

    @property
    def ship(self):
        if self.fit is not None:
            return TYPES_BY_ID.get(self.fit.split(':', 1)[0],
                                   {'name': 'Неопределен'})['name']
        return 'Неопределен'

    def refresh(self):
        callbacks, self.callbacks = self.callbacks, []
        for callback in callbacks:
            ioloop.IOLoop.instance().add_callback(callback)


class Fleet(object):

    def __init__(self, fc, fleet_type=None):
        self._fc = fc
        self.fcs = [fc]

        fc.fleet = self
        fc.is_fc = True

        if fleet_type is None:
            fleet_type = FLEET_TYPES[0]

        self.fleet_type = fleet_type

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
        for i in self.queue:
            i.refresh()

    def dequeue(self, character):
        if character in self.queue:
            self.queue.remove(character)
        for fc in self.fcs:
            fc.refresh()
        character.fleet = None
        character.refresh()
        for i in self.queue:
            i.refresh()

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
            new_fleet = get_fleet(new_fc, self.fleet_type)
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

    FREE_CHARS = set()
    ONLINE = set()

    login_required = True
    status_required = None

    @gen.coroutine
    def prepare(self):
        super(BaseHandler, self).prepare()

        self.character = self.get_secure_cookie('character', None)

        if self.character is not None:
            self.character = yield get_character(self.character.decode('utf-8'))

        if self.character is None and self.login_required:
            self.redirect('/login')

        self.check_status_required()

    def get_character_status(self):
        if self.character.fleet is None:
            if self.character not in self.FREE_CHARS:
                self.FREE_CHARS.add(self.character)
            return 'free'
        elif self.character.is_fc is True:
            if self.character in self.FREE_CHARS:
                self.FREE_CHARS.remove(self.character)
            return 'fc'
        else:
            if self.character in self.FREE_CHARS:
                self.FREE_CHARS.remove(self.character)
            return 'queue'

    def check_status_required(self):
        if self.status_required is not None:
            status = self.get_character_status()
            if status != self.status_required:
                self.redirect({
                    'free': '/',
                    'fc': '/fc',
                    'queue': '/queue',
                }[status])

    def render(self, *args, **kwargs):
        kwargs.update({
            'TITLE': TITLE,
            'FLEET_TYPES': FLEET_TYPES,
            'PREFERRED_SHIPS': PREFERRED_SHIPS,
            'FREE_CHARS': self.FREE_CHARS,
            'ONLINE': self.ONLINE,
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
    return sorted(FLEETS.values(), key=lambda x: x.fleet_type)



class BaseFreeHandler(BaseHandler):
    status_required = 'free'


class FleetsHandler(BaseFreeHandler):

    def get(self):
        self.render('fleets.html', fleets=get_fleets_list())

    def post(self):
        get_fleet(self.character, self.get_argument('fleet_type'))
        for character in self.FREE_CHARS:
            character.refresh()
        self.redirect('/fc')


class JoinHandler(BaseFreeHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('fc'))
        fleet = character.fleet
        if fleet is not None:
            if self.character in fleet.queue:
                fleet.dequeue(self.character)
            fleet.enqueue(self.character)
            self.redirect('/queue')
        else:
            self.redirect('/')

class BaseQueueHandler(BaseHandler):
    status_required = 'queue'


class LeaveHandler(BaseQueueHandler):
    def post(self):
        self.character.fleet.dequeue(self.character)
        self.redirect('/')


class QueueHandler(BaseQueueHandler):
    def get(self):
        self.render('queue.html',
                    fleet=self.character.fleet,
                    queue=self.character.fleet.queue)


class BaseFCHandler(BaseHandler):
    status_required = 'fc'


class FCHandler(BaseFCHandler):
    def get(self):
        self.render('fc.html', fleet=self.character.fleet)


class TypeHandler(BaseFCHandler):
    def post(self):
        fleet = self.character.fleet
        fleet.fleet_type = self.get_argument('fleet_type')
        for character in self.FREE_CHARS:
            character.refresh()
        self.redirect('/fc')

class DismissHandler(BaseFCHandler):
    def post(self):
        self.character.fleet.dismiss()
        for character in self.FREE_CHARS:
            character.refresh()
        self.redirect('/')


class InviteHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        self.character.fleet.dequeue(character)


class DeclineHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        self.character.fleet.dequeue(character)


class PollHandler(BaseHandler):

    @web.asynchronous
    def get(self):
        if self.character is not None:
            self.cb = stack_context.wrap(self.finish)
            if self.character not in self.ONLINE:
                self.ONLINE.add(self.character)
            self.character.callbacks.append(self.cb)
        else:
            self.finish()

    def on_connection_close(self):
        if self.cb in self.character.callbacks:
            self.character.callbacks.remove(self.cb)
            if not self.character.callbacks and self.character in self.ONLINE:
                self.ONLINE.remove(self.character)


class CharacterIDHandler(web.RequestHandler):
    @gen.coroutine
    def get(self):
        character = self.get_argument('name')
        character = yield get_character(character)
        self.finish(character.char_id)


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
        elif action == 'fleet_types':
            fleet_types = self.get_argument('fleet_types')
            for i in reversed(range(len(FLEET_TYPES))):
                FLEET_TYPES.pop(i)
            FLEET_TYPES.extend(fleet_types.splitlines())
            return self.redirect('/')
        else:
            self.send_error(400)


try:
    TYPES_BY_NAME = json.load(open('types_by_name.json'))
except:
    TYPES_BY_NAME = {}


try:
    TYPES_BY_ID = json.load(open('types_by_id.json'))
except:
    TYPES_BY_ID = {}


MODULE_RE = re.compile('((?P<q>[0-9 ]+)x )?(?P<name>.*)')



class FitHandler(BaseHandler):

    def get(self):
         self.render('fit.html')

    def post(self):
        ship = self.get_argument('ship')
        lines = self.get_argument('lines').splitlines()

        if ship not in TYPES_BY_NAME or TYPES_BY_NAME[ship]['slot'] != 'ship':
            self.render('fit.html', msg='Нет такого корабля')

        modules = {}

        for line in lines:
            m = MODULE_RE.search(line)
            if m is not None:
                if m.group('name') in TYPES_BY_NAME:
                    if m.group('name') not in modules:
                        modules[m.group('name')] = 0
                    q = 0
                    if m.group('q') is not None:
                        q = int(m.group('q'))
                    modules[m.group('name')] += q

        self.character.fit = '%d:%s::' % (TYPES_BY_NAME[ship]['id'], ':'.join(
            '%d;%d' % (TYPES_BY_NAME[name]['id'], int(q))
            for name, q in modules.items()
        ))

        for fc in self.character.fleet.fcs:
            fc.refresh()

        self.redirect('/')


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


if __name__ == "__main__":

    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)

    parse_command_line()

    application = web.Application(
        [
            (r"/", FleetsHandler),
            (r"/admin", AdminHandler),
            (r"/char_id", CharacterIDHandler),
            (r"/decline", DeclineHandler),
            (r"/dismiss", DismissHandler),
            (r"/fc", FCHandler),
            (r"/fit", FitHandler),
            (r"/invite", InviteHandler),
            (r"/join", JoinHandler),
            (r"/leave", LeaveHandler),
            (r"/login", IdentifyHandler),
            (r"/poll", PollHandler),
            (r"/queue", QueueHandler),
            (r"/type", TypeHandler),
        ],
        cookie_secret=cookie_secret,
        template_path='templates',
        static_path='static',
        ui_modules=ui,
        debug=options.devel,
        xsrf_token=True,
    )

    application.listen(options.port, options.host)

    if options.devel:

        @gen.coroutine
        def setup_fixture():
            mia, zwo = yield [get_character(u'Mia Cloks'),
                              get_character(u'Zwo Zateki')]
            try:
                get_fleet(mia, 'HQ (40)').enqueue(zwo)
            except:
                logger.debug('Fixture setup failed:', exc_info=True)

            logger.debug('Fixture setup complete.')

        ioloop.IOLoop.instance().add_callback(stack_context.wrap(setup_fixture))

    ioloop.IOLoop.instance().start()
