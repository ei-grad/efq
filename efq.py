#!/usr/bin/env python
# coding: utf-8

from datetime import timedelta
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
        FLEETS[fc] = Fleet(fc, fleet_type=None)
    return FLEETS[fc]


class Character(object):

    def __init__(self, name):
        logger.debug('Created character %s', name)
        self.name = name
        self.fleet = None
        self.is_fc = False
        self.is_admin = name in ADMINS
        self.ship_type = 'Basilisk'
        self.fit = '11985:2048;1:31366;1:16487;2:1355;1:1964;2:18672;1:31796;1:3608;4:4349;1:19231;1::'
        self.callbacks = []

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
            return 'free'
        elif self.character.is_fc is True:
            return 'fc'
        else:
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



class BaseFreeHandler(BaseHandler):
    status_required = 'free'


class FleetsHandler(BaseFreeHandler):

    def get(self):
        self.render('fleets.html', fleets=get_fleets_list())

    def post(self):
        get_fleet(self.character, self.get_argument('fleet_type'))
        self.redirect('/fc')


class JoinHandler(BaseFreeHandler):
    def post(self):
        fleet = get_character(self.get_argument('fc')).fleet
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
        self.redirect('/fc')

class DismissHandler(BaseFCHandler):
    def post(self):
        self.character.fleet.dismiss()
        self.redirect('/')


class PopHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        self.character.fleet.dequeue(character)


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
        self.render('admin.html', fleet_types=ui.FLEET_TYPES)

    @admin_required
    def post(self):
        action = self.get_argument('action')
        if action == 'fake_character':
            self.set_secure_cookie('character', self.get_argument('character'))
            self.clear_cookie('key')
            return self.redirect('/')
        elif action == 'fleet_types':
            fleet_types = self.get_argument('fleet_types')
            ui.FLEET_TYPES = fleet_types.splitlines()
            return self.redirect('/')
        else:
            self.send_error(400)


class FitHandler(BaseHandler):
    def get(self):
         pass


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


if __name__ == "__main__":

    import ui

    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)

    parse_command_line()

    application = web.Application(
        [
            (r"/", FleetsHandler),
            (r"/login", IdentifyHandler),
            (r"/queue", QueueHandler),
            (r"/join", JoinHandler),
            (r"/leave", LeaveHandler),
            (r"/fc", FCHandler),
            (r"/type", TypeHandler),
            (r"/pop", PopHandler),
            (r"/dismiss", DismissHandler),
            (r"/admin", AdminHandler),
            (r"/poll", PollHandler),
            (r"/char_id", CharacterIDHandler),
            (r"/fit", FitHandler),
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
