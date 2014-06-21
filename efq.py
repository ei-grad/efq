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

import ui


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
def get_character(charname):

    if charname not in CHARACTERS:

        logger.debug('Get character: %s', charname)

        character = Character(charname)
        CHARACTERS[charname] = character

        url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
        url = '?'.join([url, urlencode({'names': charname})])

        character.charid = yield redis.get('charid:%s' % charname)
        character.charid = native_str(character.charid)

        if character.charid is None:
            try:
                response = yield http.fetch(url)
                content = response.body.decode('utf-8')

                m = re.search(r'characterID="(\d+)"', content)
                if m is not None:
                    character.charid = m.group(1)
                    redis.set('charid:%s' % charname, character.charid)
                else:
                    raise Exception("Invalid response!")
            except:
                logger.error("Request %s failed:",
                             url, exc_info=True)

        if not character.charid or character.charid == "0":
            del CHARACTERS[charname]
            msg = "Can't get charid for %s!" % charname
            logger.error(msg)
            raise CharacterNotFound(msg)

        try:
            fit = yield redis.get('efq:fitting:%s' % charname)
            if fit:
                character.fit = native_str(fit)
        except:
            logger.error("Failed to get fit from redis!", exc_info=True)

        logger.debug(
            'Loaded character %s (%s)%s', charname, character.charid,
            ' with fitting:%s' % character.fit if character.fit else ''
        )

    raise gen.Return(CHARACTERS[charname])


FLEETS = {}


def get_fleet(fc):
    if fc not in FLEETS:
        FLEETS[fc] = Fleet(fc)
    return FLEETS[fc]


class Character(object):

    def __init__(self, charname):

        logger.debug('Creating character %s', charname)

        self.charname = charname
        self.charid = None
        self.fleet = None
        self.fit = None
        self.waitlist = {}
        self.messages = []

        self.callbacks = []
        self.events = []

    def __repr__(self):
        return '<Character:%s:%s at %s>' % (
            self.charname, self.charid, hex(id(self))
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
            'charname': self.charname,
            'fleet': self.fleet.fc.charname if self.fleet else None,
            'charid': self.charid,
            'ship': self.ship,
            'waitlist': self.waitlist,
        }
        if fit:
            d.update({
                'fit': self.fit,
            })
        return d


class Fleet(object):

    def __init__(self, fc):
        self.fc = fc
        fc.fleet = self
        self.members = [fc]
        self.queue = []
        self.fleet_type = None
        self.system = None
        self.systemid = None
        self.status = 'forming'

    def to_json(self, fit=False):
        return {
            'fc': self.fc.charname,
            'members': [i.charname for i in self.members],
            'queue': [i.charname for i in self.queue],
            'fleet_type': self.fleet_type,
            'system': self.system,
            'systemid': self.systemid,
            'status': self.status,
        }


class BaseHandler(web.RequestHandler):

    uuid = str(uuid1())

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

    fc_required = False
    admin_required = False
    trust_required = False

    @gen.coroutine
    def prepare(self):

        if self.request.remote_ip in BANNED_IPS:
            self.send_error(403)
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
        return locale.get(self.get_cookie('locale', 'ru_RU'))

    def get_character_status(self):
        if self.character is None: return 'guest'
        if self.character.fleet: return 'fleet'
        if self.character.waitlist: return 'queue'
        return 'free'

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

    def render(self, *args, **kwargs):
        default_kwargs = {
            'title': self.title,
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
        if self.character is not None:
            is_fc = self.character.is_fc
        else:
            is_fc = False
        characters = dict((i.charname, i.to_json(fit=is_fc))
                          for i in CHARACTERS.values()
                          if i.waitlist or i.fleet is not None or i.fit)
        self.render('angular.html', characters=characters)


class JsonMixin(object):
    def finish(self, data=None):
        self.set_header('Content-Type', 'application/json')
        if data is not None:
            super(JsonMixin, self).finish(json.dumps(data))
        else:
            super(JsonMixin, self).finish()


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
    optional_get_params = ['mail_auth', 'channel_auth', 'mail_auth_fc']

    def render(self, *args, **kwargs):
        kwargs['auth_channel'] = self.auth_channel
        kwargs['key'] = self.key
        if 'auth_channel_failed' not in kwargs:
            kwargs['auth_channel_failed'] = False
        kwargs['online_fcs'] = len(self.ONLINE.intersection(self.FCS))
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


MAIL_AUTH_MSG = '''Your auth link is:

http://{host}/login/token/{token}

Open it in browser in which you want to authenticate.
This link works 10 minutes since the moment when you clicked "Ask" button.
'''

MAIL_AUTH_SUBJ = 'EFQ Authentication'


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
                'character': character.to_json(),
                'message': self.locale.translate(MAIL_AUTH_MSG).format(
                    host=self.request.host,
                    token=token,
                ),
                'subject': self.locale.translate(MAIL_AUTH_SUBJ),
            })
            self.redirect('/login?' + urlencode({
                'mail_auth': 'asked',
                'mail_auth_fc': fc.charname,
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

    def post(self):
        characters = native_str(self.get_secure_cookie('character')).split(',')
        characters.remove(self.character.charname)
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/')


class BaseFreeHandler(BaseHandler):
    status_required = 'free'


class FleetsHandler(BaseFreeHandler):
    fc_required = True
    def post(self):
        fleet = get_fleet(self.character)
        fleet.fleet_type = self.get_argument('fleet_type')
        fleet.system = self.eve.get('solarsystemname')
        fleet.systemid = self.eve.get('solarsystemid')
        self.event({'action': 'new_fleet', 'fleet': fleet.to_json()})
        self.character.event({'action': 'character_invited_to_fleet',
                              'charname': self.character.charname,
                              'fleet': fleet.fc.charname})


class JoinHandler(BaseFreeHandler):
    @gen.coroutine
    def post(self):
        logger.debug(self.request.arguments)
        fc = yield get_character(self.get_argument('fleet'))
        fleet = fc.fleet
        if fleet is not None:
            if self.character in fleet.queue:
                fleet.dequeue(self.character)
            fleet.enqueue(self.character)
            self.character.event({'action': 'character_joined_fleet_queue',
                                  'charname': self.character.charname,
                                  'fleet': fc.charname})
        else:
            self.send_error(400, reason="No such fleet.")


class BaseQueueHandler(BaseHandler):
    status_required = 'queue'


class LeaveHandler(BaseQueueHandler):
    def post(self):
        fleet = self.character.fleet
        fleet.dequeue(self.character)
        self.event({'action': 'character_left_fleet',
                    'charname': self.character.charname})


class TypeHandler(BaseHandler):
    fc_required = True
    def post(self):
        fleet = self.character.fleet
        fleet.fleet_type = self.get_argument('fleet_type')
        self.event({'action': 'fleet_type_changed',
                    'fleet': fleet.fc.charname,
                    'fleet_type': fleet.fleet_type})


class DisbandHandler(BaseHandler):
    fc_required = True
    def post(self):

        fc = self.character.fleet.fc

        fleet = FLEETS[fc]

        del FLEETS[fc]

        for i in chain(fleet.queue, fleet.members):
            i.fleet = None
            self.event({'action': 'character_left_fleet',
                        'charname': i.charname})
            i.add_message("Fleet has been disbanded.")

        self.event({'action': 'del_fleet',
                    'fleet': fleet.fc.charname})


class TransferHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        charname = self.get_argument('to')
        to = yield get_character(charname)
        if to not in self.fcs:
            self.send_error(400, reason='%s is not a FC of this fleet.' % charname)
        self.character.fleet.transfer(to)
        self.redirect('/fc')


class InviteHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        fleet = self.character.fleet
        if fleet is not None:
            character = yield get_character(self.get_argument('character'))
            if character in fleet.queue:
                fleet.queue.remove(character)
            fleet.members.append(character)
            character.fleet = fleet
            character.waitlist = {}
            self.event({'action': 'character_invited_to_fleet',
                        'charname': character['charname'],
                        'fleet': fleet.fc.charname})
        else:
            self.send_error(400, reason="You are not in the fleet.")


class DeclineHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были исключены из очереди', 'danger')
        character.waitlist = {}
        self.character.fleet.dequeue(character)
        self.redirect('/fc')


class PollHandler(JsonMixin, BaseHandler):

    login_required = False

    @web.asynchronous
    def post(self):

        self.ts = float(self.get_cookie('ts')) if self.get_cookie('ts') is not None else time()
        self.timeout = None

        events = self.get_events()

        if events:
            self.finish(events)
            return

        if self.character is not None:
            if native_str(self.get_secure_cookie('uuid')) != self.uuid:
                logger.debug('Character %s has bad uuid cookie',
                             self.character.charname)
                self.set_secure_cookie('uuid', self.uuid)
                self.finish([{"action": "reload"}])
            else:
                if not self.character.callbacks:
                    self.ONLINE.add(self.character)
                self.character.callbacks.append(self.event)
        else:
            self.GUEST_CALLBACKS.add(self.event)

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
                if not self.character.callbacks:
                    self.ONLINE.remove(self.character)
        else:
            if self.event in self.GUEST_CALLBACKS:
                self.GUEST_CALLBACKS.remove(self.event)

    def on_connection_close(self):
        self.remove_callback()


class CharacterIDHandler(web.RequestHandler):
    @gen.coroutine
    def get(self):
        character = self.get_argument('charname')
        character = yield get_character(character)
        self.finish(character.charid)


class AdminHandler(TemplateMixin, LoginSuccessMixin, BaseHandler):

    template = 'admin.html'
    admin_required = True

    def post(self):
        action = self.get_argument('action')
        if action == 'fake_character':
            return self.login_success(self.get_argument('charname'))
        if action == 'ban_ip':
            BANNED_IPS.add(self.get_argument('address'))
            return self.get()
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


MODULE_RE = re.compile('((?P<q>[0-9 ]+)x )?(?P<fitname>.*)')
DNA_RE = re.compile('fitting:([0-9:;]+::)')


class FitHandler(BaseHandler):


    def get(self):
        if self.character.fit:
            fit = 'fitting:%s' % self.character.fit
        else:
            fit = ''
        self.render('fit.html', fit=fit)

    @gen.coroutine
    def post(self):

        fit = DNA_RE.search(self.get_argument('dna'))
        if fit is not None:
            fit = fit.group(1)
        else:
            self.character.add_message(self.locale.translate(
                "DNA substring was not found in your input!"
            ))
            self.get()
            raise gen.Return(None)

        self.character.fit = fit

        redis.set('efq:fitting:%s' % self.character.charname, self.character.fit)

        e = {
            'action': 'character_fit_changed',
            'charname': self.character.charname,
            'ship': self.character.ship,
            'fit': self.character.fit,
        }

        self.fc_event(e)
        self.character.event(e)

        self.redirect('/')

    def delete(self):
        redis.delete('efq:fitting:%s' % self.character.charname)
        self.get()


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
    (r"/disband", DisbandHandler),
    (r"/invite", InviteHandler),
    (r"/join", JoinHandler),
    (r"/leave", LeaveHandler),
    (r"/message", MessageHandler),
    (r"/transfer", TransferHandler),
    (r"/type", TypeHandler),

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

    if options.devel:
        HANDLERS.append((r'/devel', DevelHandler))

    if options.user:
        if options.devel:
            logger.warning('Auto-reloading with priveledge dropping is not '
                           'supported. Development mode disabled.')
            options.devel = False

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
        ui_modules=ui,
        xsrf_cookies=True,
    )

    server = httpserver.HTTPServer(application, xheaders=options.xheaders)
    server.listen(options.port, options.host)

    if options.user:
        os.setuid(pwd.getpwnam(options.user).pw_uid)

    IOLoop.instance().start()
