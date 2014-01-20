#!/usr/bin/env python
# coding: utf-8

from uuid import uuid1
from functools import wraps
import binascii
import json
import logging
import os
import re

from tornado import gen, ioloop, web, httpclient, stack_context
from tornado.options import options, define, parse_command_line
from tornado.httputil import urlencode

from toredis import Redis

import ui


logger = logging.getLogger(__name__)


DEFAULT_TITLE = 'EVE Fleet Queue'

FLEET_TYPES = ['Vanguard (10)', 'Assault (20)', 'HQ (40)']

PREFERRED_SHIPS = [
    'Vindicator',
    'Machariel',
    'Nightmar',
    'Basilisk',
    'Scimitar',
    'Vargur',
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

redis = Redis()


@gen.coroutine
def get_character(name):

    if name not in CHARACTERS:

        character = Character(name)
        CHARACTERS[name] = character

        url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
        url = '?'.join([url, urlencode({'names': name})])
        response = yield httpclient.AsyncHTTPClient().fetch(url)
        content = response.body.decode('utf-8')

        m = re.search(r'characterID="(\d+)"', content)
        if m is not None:
            character.char_id = m.group(1)
            logger.debug('Got %s char_id: %s', name, character.char_id)
        else:
            del CHARACTERS[name]
            raise Exception("Can't get char_id for %s!" % name)

        try:
            fit = yield gen.Task(redis.get, 'efq:fitting:%s' % name)
            if fit:
                character.fit = fit
        except:
            logger.error("Failed to get fit from redis!", exc_info=True)

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
        self.messages = []
        self.callbacks = []

    @property
    def ship(self):
        if self.fit is not None:
            return TYPES_BY_ID.get(self.fit.split(':', 1)[0],
                                   {'name': 'Неопределен'})['name']
        return 'Неопределен'

    def add_message(self, message, cls='info'):
        self.messages.append((str(uuid1()), message, cls))

    def remove_message(self, msgid):
        for i in list(self.messages):
            if i[0] == msgid:
                self.messages.remove(i)

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

    def dismiss(self, character, new_fc=None):

        assert character.fleet == self

        queue = self.queue
        fcs = self.fcs

        if character is self.fc:

            self.fc.fleet = None
            self.fc.is_fc = False
            self.fc.refresh()

            del FLEETS[self.fc]

            fcs.remove(self.fc)

            if new_fc is None:
                for fc in self.fcs:
                    if fc.callbacks:
                        new_fc = fc
                        break

            if new_fc is not None:

                new_fleet = get_fleet(new_fc, self.fleet_type)
                new_fleet.queue = self.queue
                new_fleet.fcs = self.fcs

                for i in fcs + queue:
                    i.fleet = new_fleet

            else:

                for i in fcs + queue:
                    i.fleet = None
                    i.is_fc = False
                    i.add_message('Флот был распущен.')

        else:

            self.fcs.remove(character)
            character.fleet = None
            character.is_fc = False

        for i in fcs:
            i.refresh()

        for i in queue:
            i.refresh()

        for i in BaseHandler.FREE_CHARS:
            i.refresh()


class BaseHandler(web.RequestHandler):

    uuid = str(uuid1())

    FREE_CHARS = set()
    ONLINE = set()
    TITLE = DEFAULT_TITLE

    login_required = True
    status_required = None

    reload_on_poll = True

    @gen.coroutine
    def prepare(self):

        super(BaseHandler, self).prepare()

        self.character = None

        name = self.get_secure_cookie('character', None)

        if name is not None:
            self.character = yield get_character(name.decode('utf-8'))

        if self.character is None and self.login_required:
            self.redirect('/login')
        else:
            self.check_status_required()

    def add_message(self, message, cls='info'):
        self.character.add_message(message, cls)

    def get_character_status(self):
        if self.character is None:
            return 'guest'
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
                    'guest': '/login',
                    'free': '/',
                    'fc': '/fc',
                    'queue': '/queue',
                }[status])

    def render(self, *args, **kwargs):
        default_kwargs = {
            'TITLE': self.TITLE,
            'FLEET_TYPES': FLEET_TYPES,
            'PREFERRED_SHIPS': PREFERRED_SHIPS,
            'FREE_CHARS': self.FREE_CHARS,
            'ONLINE': self.ONLINE,
            'reload_on_poll': self.reload_on_poll,
            'character': self.character,
            'messages': self.character.messages,
        }
        default_kwargs.update(kwargs)
        return super(BaseHandler, self).render(*args, **default_kwargs)


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
            content = response.body
            if key in content:
                character = get_identified_character(content, key)
                self.clear_cookie('key')
                self.set_secure_cookie('character', character.encode('utf-8'))
                character = yield get_character(character)
                self.render("identified.html", character=character)
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
        for i in self.FREE_CHARS + fleet.fcs + fleet.queue:
            i.refresh()
        self.redirect('/fc')


class DismissHandler(BaseFCHandler):
    def post(self):
        self.character.fleet.dismiss(self.character)
        self.redirect('/')


class InviteHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были приняты во флот', 'success')
        self.character.fleet.dequeue(character)
        self.redirect('/fc')


class DeclineHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были исключены из очереди', 'danger')
        self.character.fleet.dequeue(character)
        self.redirect('/fc')


class AddFCHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        if character.fleet is None:
            fleet = self.character.fleet
            fleet.fcs.append(character)
            character.fleet = fleet
            character.is_fc = True
            character.refresh()
        self.redirect('/fc')


class PollHandler(BaseHandler):

    @web.asynchronous
    def get(self):
        if self.character is not None:
            if self.get_secure_cookie('uuid') != self.uuid:
                self.set_secure_cookie('uuid', self.uuid)
                self.finish()
            else:
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
DNA_RE = re.compile('fitting:([0-9:;]+::)')


class FitHandler(BaseHandler):

    reload_on_poll = False

    def get(self):
        if self.character.fit:
            fit = 'fitting:%s' % self.character.fit
        else:
            fit = ''
        self.render('fit.html', fit=fit)

    def post(self):

        ship = self.get_argument('ship')
        lines = self.get_argument('lines')

        if 'fitting:' in lines:

            fit = DNA_RE.search(lines)

            if fit is not None:
                fit = fit.group(1)

        else:

            if ship not in TYPES_BY_NAME or \
               TYPES_BY_NAME[ship]['slot'] != 'ship':
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

            fit = '%d:%s::' % (
                TYPES_BY_NAME[ship]['id'],
                ':'.join(
                    '%d;%d' % (TYPES_BY_NAME[name]['id'], int(q))
                    for name, q in modules.items()
                )
            )

        self.character.fit = fit

        redis.set('efq:fitting:%s' % self.character.name,
                  self.character.fit,
                  callback=lambda x: None)

        if self.character.fleet is not None:
            for fc in self.character.fleet.fcs:
                fc.refresh()

        self.character.refresh()

        self.redirect('/')


class ReadHandler(BaseHandler):
    def post(self):
        self.character.remove_message(self.get_argument('msg'))


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


if __name__ == "__main__":

    define('title', type=str, default=DEFAULT_TITLE)
    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)

    parse_command_line()

    BaseHandler.TITLE = options.title

    application = web.Application(
        [
            (r"/", FleetsHandler),
            (r"/addfc", AddFCHandler),
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
            (r"/read", ReadHandler),
            (r"/type", TypeHandler),
        ],
        cookie_secret=cookie_secret,
        template_path='templates',
        static_path='static',
        ui_modules=ui,
        debug=options.devel,
        xsrf_cookies=True,
    )

    application.listen(options.port, options.host, xheaders=True)

    ioloop.IOLoop.instance().start()
