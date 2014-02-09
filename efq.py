#!/usr/bin/env python
# coding: utf-8

from datetime import datetime
from itertools import chain
from uuid import uuid1
from time import time
import binascii
import logging
import os
import pwd
import random
import re

import ujson as json

from tornado import gen, web, httpclient, httpserver, locale
from tornado.ioloop import IOLoop
from tornado.options import options, define, parse_command_line
from tornado.httputil import urlencode
from tornado.escape import native_str

from toredis import Redis


logger = logging.getLogger(__name__)


DEFAULT_TITLE = 'EVE Fleet Queue'
DEFAULT_AUTH_CHANNEL = 'RAISA Shield'

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

BANNED_IPS = set()

redis = Redis()


class CharacterNotFound(Exception):
    pass


http = httpclient.AsyncHTTPClient()


@gen.coroutine
def get_character(name):

    if name not in CHARACTERS:

        logger.debug('Get character: %s', name)

        character = Character(name)
        CHARACTERS[name] = character

        url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
        url = '?'.join([url, urlencode({'names': name})])

        try:
            response = yield http.fetch(url)
            content = response.body.decode('utf-8')

            m = re.search(r'characterID="(\d+)"', content)
            if m is not None:
                character.charid = m.group(1)
            else:
                raise Exception("Invalid response!")
        except:
            logger.error("Request %s failed:",
                         url, exc_info=True)

        if not character.charid or character.charid == "0":
            del CHARACTERS[name]
            msg = "Can't get charid for %s!" % name
            logger.error(msg)
            raise CharacterNotFound(msg)

        try:
            fit = yield redis.get('efq:fitting:%s' % name)
            if fit:
                character.fit = native_str(fit)
        except:
            logger.error("Failed to get fit from redis!", exc_info=True)

        logger.debug(
            'Loaded character %s (%s)%s', name, character.charid,
            ' with fitting:%s' % character.fit if character.fit else ''
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
        self.charid = None
        self.fleet = None
        self.fit = None
        self.waitlist = set()
        self.messages = []
        self.callbacks = []
        self.events = []

    def __repr__(self):
        return '<Character:%s:%s at %s>' % (
            self.name, self.charid, hex(id(self))
        )

    @property
    def is_admin(self):
        return self in BaseHandler.ADMINS

    @property
    def is_fc(self):
        return self in BaseHandler.FCS

    @property
    def ship(self):
        if self.fit is not None:
            return TYPES_BY_ID.get(native_str(self.fit).split(':', 1)[0],
                                   {'name': '-'})['name']
        return '-'

    def add_message(self, message, cls='info'):
        msg = {
            'uuid': str(uuid1()),
            'content': message,
            'cls': cls
        }
        self.messages.append(msg)
        self.event({'action': 'add_message', 'message': msg})

    def read_message(self, uuid):
        for i in list(self.messages):
            if i['uuid'] == uuid:
                self.messages.remove(i)
        self.event({'action': 'read_message', 'uuid': uuid})

    def event(self, event=None):
        if event is not None:
            self.events.append((time(), event))
        for callback in self.callbacks:
            IOLoop.current().add_callback(callback)

    def to_json(self, fit=False):
        d = {
            'name': self.name,
            'fleet': self.fleet.fc.name if self.fleet else None,
            'charid': self.charid,
            'ship': self.ship,
            'waitlist': list(self.waitlist),
        }
        if fit:
            d.update({
                'fit': self.fit,
            })
        return d


class CharacterInFleetFCS(Exception):
    def __init__(self, character):
        super(CharacterInFleetFCS, self).__init__(
            'Character %s is in fleet FCs!' % character.name,
        )


class CharacterInOtherFleet(Exception):
    def __init__(self, character):
        super(CharacterInOtherFleet, self).__init__(
            'Character %s is already in other fleet!' % character.name,
        )


class Fleet(object):

    def __init__(self, fc, fleet_type=None):

        # fc is the fleet id
        self._fc = fc

        self.fcs = [fc]

        fc.fleet = self

        self.fleet_type = "10"
        self.system = None
        self.systemid = None
        self.queue = []
        self.members = []
        self.status = 'forming'

    def to_json(self, fit=False):
        return {
            'fc': self.fc.name,
            'fcs': [i.name for i in self.fcs],
            'fleet_type': self.fleet_type,
            'system': self.system,
            'systemid': self.systemid,
            'queue': [i.name for i in self.queue],
            'members': [i.name for i in self.members],
            'status': self.status,
        }

    @property
    def fc(self):
        return self._fc

    def enqueue(self, character):
        if character in self.fcs:
            raise CharacterInFleetFCS(character)
        if character.fleet is not None and character.fleet is not self:
            raise CharacterInOtherFleet(character)
        if character in self.queue:
            self.queue.remove(character)
        self.queue.append(character)
        character.fleet = self
        character.waitlist.clear()

    def dequeue(self, character):
        if character in self.queue:
            self.queue.remove(character)
        character.fleet = None

    def transfer(self, to):
        if to not in self.fcs:
            raise Exception('%s is not a FC of this fleet!' % to.name)
        flt = get_fleet(to, self.fleet_type)
        flt.queue = self.queue
        flt.fcs = self.fcs


_DEFAULT = object()


class BaseHandler(web.RequestHandler):

    uuid = str(uuid1())

    FREE_CHARS = set()
    WAITLIST = []
    ONLINE = set()
    FCS = []
    ADMINS = []

    EVENTS = []
    FC_EVENTS = []

    GUEST_CALLBACKS = set()

    title = DEFAULT_TITLE

    login_required = True
    status_required = None

    reload_on_poll = True
    fc_required = False
    admin_required = False
    trust_required = False

    @gen.coroutine
    def prepare(self):

        if self.request.remote_ip in BANNED_IPS:
            self.send_error(500)
            raise gen.Return(None)

        self.set_cookie("_xsrf", self.xsrf_token, expires_days=30)

        self.character = None
        self.eve = {}

        self.set_header('Eve.TrustMe', 'Yes')

        self.eve['trusted'] = self.request.headers.get('Eve_trusted')

        if self.eve['trusted'] == 'Yes':
            if self.eve['trusted'] == 'Yes':
                self.eve = dict(
                    (header[4:].lower(), value)
                    for header, value in self.request.headers.get_all()
                    if header[:3] == 'Eve'
                )
        elif self.trust_required:
            self.redirect('/trust')
            raise gen.Return(None)

        logger.debug(self.eve)

        characters = self.get_secure_cookie('character', None)

        if characters:
            characters = native_str(characters).split(',')
            eve_charname = self.eve.get('charname')
            if eve_charname:
                if eve_charname in characters:
                    self.character = yield get_character(eve_charname)
            else:
                self.character = yield get_character(characters[0])

        if self.character is None and self.login_required:
            self.redirect('/login')
        elif self.admin_required and not self.character.is_admin:
            self.send_error(403)
        elif self.fc_required and not self.character.is_fc:
            self.send_error(403)
        else:
            self.check_status_required()

    def get_user_locale(self):
        return locale.get(self.get_cookie('locale'))

    def get_character_status(self):
        if self.character is None:
            return 'guest'
        if self.character.fleet is None and self.character not in self.WAITLIST:
            if self.character not in self.FREE_CHARS:
                self.FREE_CHARS.add(self.character)
            return 'free'
        else:
            if self.character in self.FREE_CHARS:
                self.FREE_CHARS.remove(self.character)
            return 'queue'

    def check_status_required(self):
        if self.status_required is not None:
            status = self.get_character_status()
            if status != self.status_required:
                self.send_error(403)

    def event(self, event):
        """Add global event."""
        self.EVENTS.append((time(), event))
        # notify characters
        for i in self.ONLINE:
            i.event()
        # notify guests
        for i in self.GUEST_CALLBACKS:
            IOLoop.current().add_callback(i)

    def fc_event(self, event):
        """Add event for FCs
        """
        self.FC_EVENTS.append((time(), event))
        for i in self.ONLINE.intersection(self.FCS):
            i.event()

    @property
    def trusted(self):
        return self.eve.get('trusted') == 'Yes'

    def add_message(self, message, cls='info'):
        self.character.add_message(message, cls)

    def get_bool(self, key, default=_DEFAULT):
        if default is _DEFAULT:
            val = self.get_argument(key)
        else:
            val = self.get_argument(key, None)

        if val is None:
            return default

        return val.lower() in ('true', '1', 'yes')

    def render(self, *args, **kwargs):
        default_kwargs = {
            'title': self.title,
            'CHARACTERS': CHARACTERS,
            'FREE_CHARS': self.FREE_CHARS,
            'ONLINE': self.ONLINE,
            'ADMINS': self.ADMINS,
            'FCS': self.FCS,
            'reload_on_poll': self.reload_on_poll,
            'trusted': self.trusted,
            'eve': self.eve,
            'character': self.character,
            'fleets': FLEETS,
            'messages': self.character.messages if self.character else [],
        }
        default_kwargs.update(kwargs)
        return super(BaseHandler, self).render(*args, **default_kwargs)


class AngularHandler(BaseHandler):
    login_required = False
    def get(self):
        if native_str(self.get_secure_cookie('uuid')) != self.uuid:
            self.set_secure_cookie('uuid', self.uuid)
        self.set_cookie('ts', '%f' % time())
        is_fc = self.character.is_fc
        characters = dict((i.name, i.to_json(fit=is_fc))
                          for i in CHARACTERS.values())
        waitlist = [i.name for i in self.WAITLIST]
        self.render('angular.html', characters=characters, waitlist=waitlist)


class JsonMixin(object):
    def finish(self, data=None):
        self.set_header('Content-Type', 'application/json')
        if data is not None:
            super(JsonMixin, self).finish(json.dumps(data))
        else:
            super(JsonMixin, self).finish()


class WaitlistHandler(JsonMixin, BaseHandler):

    def get(self):
        self.finish(list(self.character.waitlist))

    def post(self):
        fleet_type = self.get_argument('fleet_type')
        if fleet_type not in self.character.waitlist:
            self.character.add_message((
                'You have been added to a common %s fleets waitlist.'
            ) % fleet_type)
            self.character.waitlist.add(fleet_type)
        else:
            self.character.add_message(
                'You have left a common %s fleets waitlist.' % fleet_type
            )
            self.character.waitlist.remove(fleet_type)

        if self.character.waitlist:
            if self.character not in self.WAITLIST:
                self.WAITLIST.append(self.character)
        else:
            if self.character in self.WAITLIST:
                self.WAITLIST.remove(self.character)

        e = {
            'action': 'user_waitlist_changed',
            'charname': self.character.name,
            'waitlist': list(self.character.waitlist),
        }

        self.event(e)

        self.get()


class TrustHandler(BaseHandler):

    login_required = False

    def get(self):
        if self.trusted:
            self.redirect('/')
        else:
            self.render('trust.html')


class LoginSuccessMixin(object):
    def login_success(self, charname):
        characters = self.get_secure_cookie('character')
        if characters:
            characters = set(native_str(characters).split(','))
        else:
            characters = set()
        characters.add(charname)
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/login/success')


def generate_token(length):
    return native_str(binascii.b2a_hex(os.urandom(length)))


class BaseLoginHandler(LoginSuccessMixin, BaseHandler):
    login_required = False
    auth_channel = DEFAULT_AUTH_CHANNEL


class TemplateMixin(object):

    optional_get_params = []

    def get(self):
        self.render(self.template, **dict(
            (i, self.get_argument(i, None))
            for i in self.optional_get_params
        ))


class ChannelAuthKeyMixin(object):
    def prepare(self):
        self.key = native_str(self.get_secure_cookie('key'))
        if self.key is None:
            self.key = generate_token(8)
            self.set_secure_cookie('key', self.key)
        return super(ChannelAuthKeyMixin, self).prepare()


class LoginHandler(ChannelAuthKeyMixin, TemplateMixin, BaseLoginHandler):
    template = 'login.html'
    optional_get_params = ['mail_auth', 'channel_auth']

    def render(self, *args, **kwargs):
        kwargs['auth_channel'] = self.auth_channel
        kwargs['key'] = self.key
        if 'auth_channel_failed' not in kwargs:
            kwargs['auth_channel_failed'] = False
        super(BaseLoginHandler, self).render(*args, **kwargs)


class LoginSuccessHandler(TemplateMixin, BaseHandler):
    template = 'login_success.html'


class ChannelAuthHandler(ChannelAuthKeyMixin, BaseLoginHandler):

    @gen.coroutine
    def get_chat_logs(self):
        url = "http://eve-live.com/%s" % self.auth_channel.replace(" ", "_")
        response = yield http.fetch(url)
        raise gen.Return(response)

    @gen.coroutine
    def post(self):

        response = yield gen.Task(self.get_chat_logs)
        content = native_str(response.body)
        r = native_str(
            r'<a href="/%s/p/([^"]+)" style="color:#FC3;">([^>]+)</a>'
            r'&gt; %s </td>'
        )
        r = r % (self.auth_channel.replace(' ', '_'), self.key)
        m = re.search(r, content)

        if m is not None and m.group(2) == m.group(1).replace('_', ' '):
            charname = m.group(2)
            self.clear_cookie('key')
            logger.debug('%s has been authenticated with EVE headers: %s',
                         charname, self.eve)
            self.login_success(charname)
        else:
            self.redirect("/login?channel_auth=failed")


class MailAuthAskHandler(BaseLoginHandler):
    @gen.coroutine
    def post(self):

        online_fcs = list(self.ONLINE.intersection(self.FCS))

        if online_fcs:

            if self.trusted:
                charname = self.eve.get('charname')
            else:
                charname = self.get_argument('charname')

            character = yield get_character(charname)

            token = generate_token(16)

            logger.debug('Auth link for %s: http://%s/login/token/%s',
                         charname, self.request.host, token)

            k = 'efq:mail_auth_token:%s' % token
            redis.set(k, charname)
            redis.expire(k, 600)
            fc = random.choice(online_fcs)
            fc.event({
                'action': 'mail_auth_request',
                'token': token,
                'character': character.to_json(),
            })
            self.redirect('/login?' + urlencode({
                'mail_auth': 'asked',
                'fc': fc.name
            }))
        else:
            self.redirect('/login?mail_auth=no_fc_online')


class MailAuthHandler(BaseLoginHandler):
    @gen.coroutine
    def get(self, token):
        k = 'efq:mail_auth_token:%s' % token
        charname = yield redis.get(k)
        if charname:
            charname = charname.decode('utf-8')
            if self.trusted and self.eve['charname'] != charname:
                reason = "%s tried to authenticate as %s!" % (
                    self.eve['charname'], charname
                )
                logger.warning(reason)
                self.send_error(400, reason=reason)
            else:
                redis.delete(k)
                self.login_success(charname)
        else:
            self.send_error(400, reason="Bad token!")


class LogoutHandler(TemplateMixin, BaseHandler):

    template = 'logout.html'
    reload_on_poll = False

    def post(self):
        characters = native_str(self.get_secure_cookie('character')).split(',')
        characters.remove(self.character.name)
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/')


class BaseFreeHandler(BaseHandler):
    status_required = 'free'


class FleetsHandler(BaseFreeHandler):
    fc_required = True
    def post(self):
        fleet = get_fleet(self.character, self.get_argument('fleet_type'))
        fleet.system = self.eve.get('solarsystemname')
        fleet.systemid = self.eve.get('solarsystemid')
        self.event({'action': 'new_fleet', 'fleet': fleet.to_json()})
        self.character.event({'action': 'update_character',
                              'charname': self.character.name,
                              'fleet': fleet.fc.name})


class JoinHandler(BaseFreeHandler):
    @gen.coroutine
    def post(self):
        logger.debug(self.request.arguments)
        fc = yield get_character(self.get_argument('fleet'))
        if fc.fleet is not None:
            if self.character in fc.fleet.queue:
                fc.fleet.dequeue(self.character)
            fc.fleet.enqueue(self.character)
            self.character.event({'action': 'update_character',
                                  'charname': self.character.name,
                                  'fleet': fc.name})
        else:
            self.send_error(400, reason="No such fleet.")


class BaseQueueHandler(BaseHandler):
    status_required = 'queue'


class LeaveHandler(BaseQueueHandler):
    def post(self):
        fleet = self.character.fleet
        fleet.dequeue(self.character)
        self.event({'action': 'update_fleet',
                    'fleet': fleet.to_json()})
        self.event({'action': 'update_character',
                    'charname': self.character.name,
                    'fleet': None})


class TypeHandler(BaseHandler):
    fc_required = True
    def post(self):
        fleet = self.character.fleet
        fleet.fleet_type = self.get_argument('fleet_type')
        self.event({'action': 'update_fleet',
                    'fleet': fleet.fc.name,
                    'fleet_type': fleet.fleet_type})


class DismissHandler(BaseHandler):
    fc_required = True
    def post(self, fc):

        fleet = FLEETS[fc]

        del FLEETS[fc]

        for i in chain(fleet.fcs, fleet.queue, fleet.members):
            i.fleet = None
            i.add_message('Флот был распущен.')

        for i in self.ONLINE:
            i.event({'action': 'remove_fleet', 'fleet': fleet.fc.name})

        self.redirect('/')


class TransferHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        name = self.get_argument('to')
        to = yield get_character(name)
        if to not in self.fcs:
            self.send_error(400, reason='%s is not a FC of this fleet.' % name)
        self.character.fleet.transfer(to)
        self.redirect('/fc')


class InviteHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были приняты во флот', 'success')
        self.character.fleet.dequeue(character)
        self.redirect('/fc')


class DeclineHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были исключены из очереди', 'danger')
        self.character.fleet.dequeue(character)
        self.redirect('/fc')


class PollHandler(JsonMixin, BaseHandler):

    login_required = False

    @web.asynchronous
    def get(self):

        self.ts = float(self.get_cookie('ts')) if self.get_cookie('ts') is not None else time()
        self.timeout = None

        events = self.get_events()

        if events:
            self.finish(events)
            return

        if self.character is not None:
            if native_str(self.get_secure_cookie('uuid')) != self.uuid:
                logger.debug('Character %s has bad uuid cookie',
                             self.character.name)
                self.set_secure_cookie('uuid', self.uuid)
                self.finish([{"action": "reload"}])
            else:
                if self.character not in self.ONLINE:
                    self.ONLINE.add(self.character)
                self.character.callbacks.append(self.event)
        else:
            self.GUEST_CALLBACKS.append(self.event)

    def filter_events(self, events):
        return list(filter(lambda x: x[0] >= self.ts, events))

    def get_events(self):
        events = self.filter_events(self.EVENTS)
        if self.character:
            events.extend(self.filter_events(self.character.events))
            if self.character.is_fc:
                events.extend(self.filter_events(self.FC_EVENTS))
        events.sort(key=lambda x: x[0])
        return list(i[1] for i in events)

    def event(self):
        if self._finished:
            return
        events = self.get_events()
        if events:
            if time() - self.ts < 0.3:
                if self.timeout is None:
                    self.timeout = IOLoop.instance().add_timeout(
                        datetime.now() - datetime.fromtimestamp(self.ts),
                        self.event,
                    )
                return
            self.finish(events)

    def finish(self, events=None):
        if events is not None:
            self.remove_callback()
            self.set_cookie('ts', '%f' % time())
            super(PollHandler, self).finish(events)
        else:
            super(PollHandler, self).finish()

    def remove_callback(self):
        if self.character:
            if self.event in self.character.callbacks:
                self.character.callbacks.remove(self.event)
                if not self.character.callbacks and self.character in self.ONLINE:
                    self.ONLINE.remove(self.character)
        else:
            if self.event in self.GUEST_CALLBACKS:
                self.GUEST_CALLBACKS.remove(self.event)

    def on_connection_close(self):
        self.remove_callback()


class CharacterIDHandler(web.RequestHandler):
    @gen.coroutine
    def get(self):
        character = self.get_argument('name')
        character = yield get_character(character)
        self.finish(character.charid)


class AdminHandler(TemplateMixin, LoginSuccessMixin, BaseHandler):

    template = 'admin.html'
    admin_required = True

    def post(self):
        action = self.get_argument('action')
        if action == 'fake_character':
            return self.login_success(self.get_argument('charname'))
        else:
            self.send_error(400)

class DevelHandler(AdminHandler):
    login_required = False
    admin_required = False


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

    @gen.coroutine
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

        redis.set('efq:fitting:%s' % self.character.name, self.character.fit)

        e = {
            'action': 'fit_updated',
            'charname': self.character.name,
            'ship': self.character.ship,
            'fit': self.character.fit,
        }

        self.fc_event(e)
        self.character.event(e)

        self.redirect('/')


class MessageHandler(BaseHandler):
    def post(self):
        self.character.read_message(native_str(self.get_argument('uuid')))


try:
    cookie_secret = open('.cookie_secret', 'rb').read()
except:
    cookie_secret = os.urandom(8)
    with open('.cookie_secret', 'wb') as f:
        f.write(cookie_secret)


HANDLERS = [
    (r"/", AngularHandler),
    (r"/admin", AdminHandler),
    (r"/fit", FitHandler),
    (r"/login", LoginHandler),
    (r"/trust", TrustHandler),


    (r"/fleets", FleetsHandler),
    (r"/decline", DeclineHandler),
    (r"/dismiss", DismissHandler),
    (r"/invite", InviteHandler),
    (r"/join", JoinHandler),
    (r"/leave", LeaveHandler),
    (r"/message", MessageHandler),
    (r"/transfer", TransferHandler),
    (r"/type", TypeHandler),
    (r"/waitlist", WaitlistHandler),

    (r"/login/channel_auth", ChannelAuthHandler),
    (r"/login/mail_auth", MailAuthAskHandler),
    (r"/login/token/([0-9a-f]+)", MailAuthHandler),
    (r"/login/success", LoginSuccessHandler),
    (r"/logout", LogoutHandler),

    (r"/poll", PollHandler),
]


if __name__ == "__main__":

    httpclient.AsyncHTTPClient.configure(
        "tornado.curl_httpclient.CurlAsyncHTTPClient"
    )

    define('title', type=str, default=DEFAULT_TITLE)
    define('channel', type=str, default=DEFAULT_AUTH_CHANNEL)
    define('devel', type=bool, default=False)
    define('host', type=str, default='localhost')
    define('port', type=int, default=8888)
    define('user', type=str, default='')
    define('xheaders', type=bool, default=False)

    parse_command_line()

    if options.user:
        if options.devel:
            logger.warning('Auto-reloading with priveledge dropping is not '
                           'supported. Development mode disabled.')
            options.devel = False

    if options.devel:
        HANDLERS.append((r'/devel', DevelHandler))

    #logging.getLogger('tornado.general').setLevel(logging.INFO)

    BaseHandler.title = options.title
    LoginHandler.auth_channel = options.channel

    for i in ADMINS:
        get_character(i, callback=BaseHandler.ADMINS.append)

    for i in FCS:
        get_character(i, callback=BaseHandler.FCS.append)

    locale.load_gettext_translations('i18n', 'messages')

    application = web.Application(
        HANDLERS,
        cookie_secret=cookie_secret,
        template_path='templates',
        static_path='static',
        debug=options.devel if not options.user else False,
        xsrf_cookies=True,
    )

    server = httpserver.HTTPServer(application, xheaders=options.xheaders)
    server.listen(options.port, options.host)

    if options.user:
        os.setuid(pwd.getpwnam(options.user).pw_uid)

    IOLoop.instance().start()
