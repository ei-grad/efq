#!/usr/bin/env python
# coding: utf-8

from itertools import chain
from uuid import uuid1
import binascii
import logging
import os
import pwd
import random
import re

import ujson as json

from tornado import gen, ioloop, web, httpclient, httpserver, stack_context
from tornado.options import options, define, parse_command_line
from tornado.httputil import urlencode
from tornado.escape import native_str

from toredis import Redis

import ui


logger = logging.getLogger(__name__)


DEFAULT_TITLE = 'EVE Fleet Queue'
DEFAULT_AUTH_CHANNEL = 'RAISA Shield'

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
    u'Yart Skord',
    u'Alex Amato',
    u'Pavel Leopa',
    u'Xilia Otsu',
    u'Korami Barbokan',
]

FCS = ADMINS + [
    u'Grim Hinken',
    u'Bellatrix Atria',
    u'Cloned S0ul',
    u'DarkMishgan',
    u'Dark Saiber',
    u'Djokart',
    u'Eva Pride',
    u'Kobius',
    u'Lexiboth Hita',
    u'Mikhail MustDie',
    u'Samarys Flint',
    u'Serg Uitra',
    u'Sheryl Niome',
    u'Tech Ostus',
    u'Trong Sa',
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

        try:
            response = yield httpclient.AsyncHTTPClient().fetch(url)
            content = response.body.decode('utf-8')

            m = re.search(r'characterID="(\d+)"', content)
            if m is not None:
                character.charid = m.group(1)
            else:
                raise Exception("Invalid response!")
        except:
            logger.error("Request to api.eveonline.com failed:", name, exc_info=True)

        if not character.charid or character.charid == "0":
            del CHARACTERS[name]
            msg = "Can't get charid for %s!" % name
            logger.error(msg)
            raise Exception(msg)

        try:
            fit = yield gen.Task(redis.get, 'efq:fitting:%s' % name)
            if fit:
                character.fit = fit
        except:
            logger.error("Failed to get fit from redis!", exc_info=True)

        logger.debug(
            'Loaded character %s (%s) %s', name, character.charid,
            'with fitting:%s' % character.fit if character.fit else 'without fit'
        )

    raise gen.Return(CHARACTERS[name])


FLEETS = {}


def get_fleet(fc, fleet_type=None):
    if fc not in FLEETS:
        FLEETS[fc] = Fleet(fc, fleet_type=fleet_type)
    return FLEETS[fc]


class Character(object):

    def __init__(self, name):
        logger.debug('Creating character %s', name)
        self.name = name
        self.fleet = None
        self.is_fc = False
        self.fit = None
        self.charid = None
        self.messages = []
        self.callbacks = []

    def __repr__(self):
        return '<Character:%s:%s at %s>' % (self.name, self.charid, id(self))

    def is_admin(self):
        return self in BaseHandler.ADMINS

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

    def refresh(self, data=None):
        callbacks, self.callbacks = self.callbacks, []
        for callback in callbacks:
            if data is not None:
                orig_callback = callback
                callback = lambda: orig_callback(data)
            ioloop.IOLoop.instance().add_callback(callback)

    def to_json(self, include_fit=False):
        d = {
            'name': self.name,
            'fleet': self.fleet.fc.name if self.fleet else None,
            'is_fc': self.is_fc,
            'is_admin': self.is_admin,
            'charid': self.charid,
        }
        if include_fit:
            d['fit'] = self.fit
        return d


class Fleet(object):

    def __init__(self, fc, fleet_type=None):

        # fc is the fleet id
        self._fc = fc

        self.fcs = [fc]

        fc.fleet = self
        fc.is_fc = True

        if fleet_type is None:
            fleet_type = FLEET_TYPES[0]

        self.fleet_type = fleet_type

        self.queue = []

    def to_json(self):
        return {
            'fleet_type': self.fleet_type,
            'fc': self.fc.name,
            'fcs': [i.name for i in self.fcs],
            'queue': [i.name for i in self.queue],
        }

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

    def transfer(self, to):

        if to not in self.fcs:
            raise Exception('%s is not a FC of this fleet!' % to.name)

        flt = get_fleet(to, self.fleet_type)
        flt.queue = self.queue
        flt.fcs = self.fcs

        for i in chain(self.fcs, self.queue, self.fc):
            i.fleet = flt
            i.refresh()

    def dismiss(self):

        del FLEETS[self.fc]

        for i in chain(self.fcs, self.queue):
            i.fleet = None
            i.is_fc = False
            i.add_message('Флот был распущен.')

        for i in chain(self.fcs, self.queue, BaseHandler.FREE_CHARS):
            i.refresh()


class BaseHandler(web.RequestHandler):

    uuid = str(uuid1())

    FREE_CHARS = set()
    ONLINE = set()
    FCS = []
    ADMINS = []

    title = DEFAULT_TITLE

    login_required = True
    status_required = None

    reload_on_poll = True
    fc_required = False
    admin_required = False
    trust_required = True

    @gen.coroutine
    def prepare(self):

        super(BaseHandler, self).prepare()

        logger.debug(self.request.headers)

        self.character = None
        self.eve = {}

        self.set_header('Eve.TrustMe', 'Yes')

        self.eve['trusted'] = self.request.headers.get('Eve_trusted')

        if self.eve['trusted'] == 'Yes' or not self.trust_required:

            if self.eve['trusted'] == 'Yes':
                self.eve = dict(
                    (header[4:].lower(), value)
                    for header, value in self.request.headers.get_all()
                    if header[:3] == 'Eve'
                )

            characters = self.get_secure_cookie('character', None)

            if characters:
                characters = native_str(characters).split(',')
                if self.eve.get('charname') in characters:
                    name = self.eve['charname']
                    self.character = yield get_character(name)

            if self.character is None and self.login_required:
                self.redirect('/login')
            elif self.admin_required and self.character.name not in ADMINS:
                self.send_error(403)
            elif self.fc_required and self.character.name not in FCS:
                self.send_error(403)
            else:
                self.check_status_required()

        else:
            self.redirect('/trust')

    @property
    def trusted(self):
        return self.eve['trusted'] == 'Yes'

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
            'title': self.title,
            'FLEET_TYPES': FLEET_TYPES,
            'PREFERRED_SHIPS': PREFERRED_SHIPS,
            'FREE_CHARS': self.FREE_CHARS,
            'ONLINE': self.ONLINE,
            'ADMINS': self.ADMINS,
            'FCS': self.FCS,
            'reload_on_poll': self.reload_on_poll,
            'trusted': self.trusted,
            'eve': self.eve,
            'character': self.character,
            'messages': self.character.messages if self.character else [],
        }
        default_kwargs.update(kwargs)
        return super(BaseHandler, self).render(*args, **default_kwargs)


class TrustHandler(BaseHandler):
    login_required = False
    trust_required = False
    def get(self):
        if self.trusted:
            self.redirect('/')
        else:
            self.render('trust.html')


class BaseLoginHandler(BaseHandler):

    status_required = 'guest'
    login_required = False
    auth_channel = DEFAULT_AUTH_CHANNEL

    def generate_token(self, length):
        return binascii.b2a_hex(os.urandom(length))

    def prepare(self):
        super(BaseLoginHandler, self).prepare()
        self.key = self.get_secure_cookie('key')
        if self.key is None:
            self.key = self.generate_token(8)
            self.set_secure_cookie('key', self.key)

    def render(self, *args, **kwargs):
        kwargs['auth_channel'] = self.auth_channel
        kwargs['key'] = self.key
        if 'auth_channel_failed' not in kwargs:
            kwargs['auth_channel_failed'] = False
        super(BaseLoginHandler, self).render(*args, **kwargs)

    def login_success(self, character):
        characters = self.get_secure_cookie('character')
        if characters is not None:
            characters = set(characters.split(','))
        else:
            characters = set()
        characters.add(character)
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/login/success')


class TemplateMixin(object):
    optional_get_params = []
    def get(self):
        self.render(self.template, **dict(
            (i, self.get_argument(i, None))
            for i in self.optional_get_params
        ))


class LoginHandler(TemplateMixin, BaseLoginHandler):
    template = 'login.html'
    optional_get_params = ['mail_auth', 'channel_auth']


class LoginSuccessHandler(TemplateMixin, BaseHandler):
    template = 'login_success.html'


class ChannelAuthHandler(BaseLoginHandler):

    @gen.coroutine
    def get_chat_logs(self):
        url = "http://eve-live.com/%s" % self.auth_channel.replace(" ", "_")
        response = yield httpclient.AsyncHTTPClient().fetch(url)
        raise gen.Return(response)

    @gen.coroutine
    def post(self):

        response = yield gen.Task(self.get_chat_logs)
        content = response.body

        r = native_str(
            r'<a href="/%s/p/([^"]+)" style="color:#FC3;">([^>]+)</a>'
            r'&gt; %s </td>'
        )
        r = r % (self.auth_channel.replace(' ', '_'), native_str(self.key))

        m = re.search(r, native_str(content))

        if m is not None and m.group(2) == m.group(1).replace('_', ' '):
            character = m.group(2)
            self.clear_cookie('key')
            logger.debug('%s has been authenticated with EVE headers: %s',
                         character, self.eve)
            self.login_success(character)
        else:
            self.redirect("/login?channel_auth=failed")


class MailAuthAskHandler(BaseLoginHandler):
    def post(self):
        token = self.generate_token(16)
        k = 'efq:mail_auth_token:%s:%s' % (self.eve['charname'], token)
        redis.set(k, "")
        redis.expire(k, 600)
        online_fcs = list(self.ONLINE.intersection(self.FCS))
        if online_fcs:
            fc = random.choice(online_fcs)
            fc.refresh({
                'mail_auth_request': {
                    'token': token,
                    'character': self.eve['charname'],
                    'charid': self.eve['charid'],
                }
            })
            self.redirect('/login?' + urlencode({
                'mail_auth': 'asked',
                'fc': fc.name
            }))
        else:
            self.redirect('/login?mail_auth=no_fc_online')


class MailAuthHandler(BaseLoginHandler):
    @gen.coroutine
    def get(self, name, token):
        if self.eve['charname'] == name:
            k = 'efq:mail_auth_token:%s:%s' % (name, token)
            correct = yield redis.get(k)
            if correct is not None:
                self.login_success(name)
            else:
                self.send_error(400, reason="Bad token!")
        else:
            reason="%s to authenticate as %s!" % (self.eve['name'], name)
            self.send_error(400, reason=reason)


class LogoutHandler(TemplateMixin, BaseHandler):

    template = 'logout.html'
    reload_on_poll = False

    def post(self):
        characters = self.get_secure_cookie('character').split(',')
        characters.remove(self.character.name)
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/')


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


class JSONHandler(BaseHandler):
    def finish(self, data):
        super(JSONHandler, self).finish(json.dumps(data))


class FleetsJSONHandler(JSONHandler):
    def get(self):
        self.finish(dict((i.fc.name, i.to_json()) for i in get_fleets_list()))


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
    fc_required = True


class FCHandler(BaseFCHandler):
    def get(self):
        self.render('fc.html', fleet=self.character.fleet)


class TypeHandler(BaseFCHandler):
    def post(self):
        fleet = self.character.fleet
        fleet.fleet_type = self.get_argument('fleet_type')
        for i in chain(self.FREE_CHARS, fleet.fcs, fleet.queue):
            i.refresh()
        self.redirect('/fc')


class DismissHandler(BaseFCHandler):
    def post(self):
        self.character.fleet.dismiss()
        self.redirect('/')


class TransferHandler(BaseFCHandler):
    @gen.coroutine
    def post(self):
        name = self.get_argument('to')
        to = yield get_character(name)
        if to not in self.fcs:
            self.send_error(400, reason='%s is not a FC of this fleet.' % name)
        self.character.fleet.transfer(to)
        self.redirect('/fc')


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
        fleet = self.character.fleet
        if character.fleet is None or character.fleet == fleet:
            character.add_message('%s сделал вас ФК' % self.character.name)
            fleet.fcs.append(character)
            character.fleet = fleet
            character.is_fc = True
            for i in fleet.fcs:
                i.refresh()
        else:
            self.add_message('%s уже находится в другом флоте.')
        self.redirect('/fc')


class PollHandler(BaseHandler):

    @web.asynchronous
    def get(self):
        if self.character is not None:
            self.set_header('Content-Type', 'application/json')
            if self.get_secure_cookie('uuid') != self.uuid:
                self.set_secure_cookie('uuid', self.uuid)
                self.finish('{"action": "reload"}')
            else:
                if self.character not in self.ONLINE:
                    self.ONLINE.add(self.character)
                self.cb = stack_context.wrap(self.finish)
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
        self.finish(character.charid)


class AdminHandler(TemplateMixin, BaseHandler):

    template = 'admin.html'
    admin_required = True

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
                self.add_message('Нет такого корабля', 'danger')
                self.render('fit.html')

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


HANDLERS = [
    (r"/", FleetsHandler),
    (r"/addfc", AddFCHandler),
    (r"/admin", AdminHandler),
    (r"/charid", CharacterIDHandler),
    (r"/decline", DeclineHandler),
    (r"/dismiss", DismissHandler),
    (r"/fc", FCHandler),
    (r"/fit", FitHandler),
    (r"/invite", InviteHandler),
    (r"/join", JoinHandler),
    (r"/leave", LeaveHandler),
    (r"/login", LoginHandler),
    (r"/login/channel_auth", ChannelAuthHandler),
    (r"/login/mail_auth", MailAuthAskHandler),
    (r"/login/success", LoginSuccessHandler),
    (r"/logout", LogoutHandler),
    (r"/poll", PollHandler),
    (r"/queue", QueueHandler),
    (r"/read", ReadHandler),
    (r"/transfer", TransferHandler),
    (r"/trust", TrustHandler),
    (r"/type", TypeHandler),
]


if __name__ == "__main__":

    httpclient.AsyncHTTPClient.configure("tornado.curl_httpclient.CurlAsyncHTTPClient")

    define('title', type=str, default=DEFAULT_TITLE)
    define('channel', type=str, default=DEFAULT_AUTH_CHANNEL)
    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)
    define('user', type=str, default='')

    parse_command_line()

    logging.getLogger('tornado.general').setLevel(logging.INFO)

    BaseHandler.title = options.title
    LoginHandler.auth_channel = options.channel

    for i in ADMINS:
         get_character(i, callback=BaseHandler.ADMINS.append)

    for i in FCS:
         get_character(i, callback=BaseHandler.FCS.append)

    application = web.Application(
        HANDLERS,
        cookie_secret=cookie_secret,
        template_path='templates',
        static_path='static',
        ui_modules=ui,
        debug=options.devel if not options.user else False,
        xsrf_cookies=True,
    )

    server = httpserver.HTTPServer(application, xheaders=True)
    server.listen(options.port, options.host)

    if options.user:
        if options.devel:
            logger.warning('Auto-reloading with priveledge dropping is not '
                           'supported. Development mode disabled.')
        os.setuid(pwd.getpwnam(options.user).pw_uid)

    ioloop.IOLoop.instance().start()
