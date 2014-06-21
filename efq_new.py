#!/usr/bin/env python
# coding: utf-8

from datetime import datetime
from itertools import chain
from uuid import uuid1 as get_uuid
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
REDIS_PREFIX = 'efq'


# TODO: get/update from redis
ADMINS = []
FCS = []
BANNED_IPS = set()


redis = Redis()


class CharacterNotFound(Exception):
    pass


class FleetNotFound(Exception):
    pass


http = httpclient.AsyncHTTPClient()


def rk_character(charname):
    return '%s:character:%s' % (REDIS_PREFIX, charname)


def rk_character_ml(charname):
    return '%s:character_ml:%s' % (REDIS_PREFIX, charname)


def rk_character_mh(charname):
    return '%s:character_mh:%s' % (REDIS_PREFIX, charname)


def rk_fleet(fleet_id):
    return '%s:fleet:%s' % (REDIS_PREFIX, fleet_id)


def rk_fleet_queue(fleet_id):
    return '%s:fleet_queue:%s' % (REDIS_PREFIX, fleet_id)


def rk_fleet_members(fleet_id):
    return '%s:fleet_members:%s' % (REDIS_PREFIX, fleet_id)


@gen.coroutine
def get_character(name):

    logger.debug('Get character: %s', name)

    character = yield redis.hgetall(rk_character('charname'))

    if character is None:
        character = {'charname': name}
    else:
        character['charname'] = name

    if not character.get('charid'):

        url = "https://api.eveonline.com/eve/CharacterID.xml.aspx"
        url = '?'.join([url, urlencode({'names': name})])

        try:

            response = yield http.fetch(url)
            content = response.body.decode('utf-8')

            m = re.search(r'characterID="(\d+)"', content)
            if m is not None:
                character['charid'] = m.group(1)
                redis.hset(rk_character(name), 'charid', character['charid'])
            else:
                raise Exception("Invalid EVE API response!")

        except:
            logger.error("Request %s failed:", url, exc_info=True)

    if not character.get('charid') or character.get('charid') == "0":
        msg = "Can't get charid for %s!" % name
        logger.error(msg)
        raise CharacterNotFound(msg)

    logger.debug(
        'Loaded character %s (%s)%s', name, character.get('charid'),
        ' with fitting:%s' % (
            character.get('fitting') if character.get('fitting') else ''
        )
    )

    raise gen.Return(character)


@gen.coroutine
def get_fleet(fleet_id, fit=False):
    fleet, queue, members = yield [
        redis.hgetall(rk_fleet(fleet_id)),
        redis.lget(rk_fleet_queue(fleet_id)),
        redis.lget(rk_fleet_members(fleet_id))
    ]
    if fleet is None:
        raise FleetNotFound()
    ret = {
        'id': fleet_id,
        'fc': None,
        'boss': None,
        'fleet_type': '10',
        'system': None,
        'systemid': None,
        'status': 'forming',
    }
    ret.update(fleet)
    ret.update({
        'queue': queue if queue is not None else [],
        'members': members if members is not None else [],
    })
    return ret


_DEFAULT = object()


class BaseHandler(web.RequestHandler):

    uuid = ''

    USER_CALLBACKS = list()
    FC_CALLBACKS = list()
    GUEST_CALLBACKS = list()

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
            self.send_error(403)
            raise gen.Return(None)

        self.set_cookie("_xsrf", self.xsrf_token, expires_days=30)

        self.character = None
        self.fleet = None
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

        if self.character is not None and self.character.get('fleet'):
            self.fleet = yield get_fleet(self.character.get('fleet'))

        if self.character is None and self.login_required:
            self.redirect('/login')
        elif self.admin_required and not self.character['name'] not in ADMINS:
            self.send_error(403)
        elif self.fc_required and not self.character['name'] not in FCS:
            self.send_error(403)
        else:
            self.character_status = self.get_character_status()
            self.check_status_required(self.character_status)

    def get_user_locale(self):
        return locale.get(self.get_cookie('locale'))

    def get_character_status(self):
        if self.character is None:
            return 'guest'
        elif self.character['fleet'] is None:
            if self.character['waitlist']:
                return 'in waitlist'
            else:
                return 'free'
        elif self.character['charname'] in self.fleet.members:
            return 'in members'
        elif self.character['charname'] in self.fleet.queue:
            return 'in queue'
        else:
            raise Exception('Unknown character status!')

    def check_status_required(self, status):
        if self.status_required is not None:
            if status != self.status_required:
                reason = "You should be %s to do this!" % self.status_required
                self.send_error(403, reason=reason)

    def event(self, event):
        """Add global event."""
        self.EVENTS.append((time(), event))
        ioloop = IOLoop.current()
        # notify characters
        for i in self.USER_CALLBACKS:
            ioloop.add_callback(i)
        # notify guests
        for i in self.GUEST_CALLBACKS:
            ioloop.add_callback(i)

    def fc_event(self, event):
        """Add event for FCs
        """
        self.FC_EVENTS.append((time(), event))
        ioloop = IOLoop.current()
        for i in self.FC_CALLBACKS:
            ioloop.add_callback(i)

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
            'reload_on_poll': self.reload_on_poll,
            'trusted': self.trusted,
            'eve': self.eve,
            'character': self.character,
            'fleets': self.fleets,
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
            self.character.waitlist.add(fleet_type)
        else:
            self.character.waitlist.remove(fleet_type)

        if self.character.waitlist:
            if self.character not in self.WAITLIST:
                self.WAITLIST.append(self.character)
        else:
            if self.character in self.WAITLIST:
                self.WAITLIST.remove(self.character)

        e = {
            'action': 'character_waitlist_changed',
            'charname': self.character['charname'],
            'waitlist': list(sorted(self.character.waitlist)),
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

        online_fcs = list(self.ONLINE.intersection(FCS))

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
        characters.remove(self.character['charname'])
        self.set_secure_cookie('character', ','.join(characters))
        self.redirect('/')


class BaseFreeHandler(BaseHandler):
    status_required = 'free'


class FleetsHandler(BaseFreeHandler):

    fc_required = True

    @gen.coroutine
    def post(self):

        if self.character.fleet:
            self.add_message("You are already in the fleet!", 'error')
            self.send_error(400, reason="You are already in the fleet!")
            return

        fleet = Fleet(self.character['charname'])
        fleet.fleet_type = self.get_argument('fleet_type')
        fleet.system = self.eve.get('solarsystemname')
        fleet.systemid = self.eve.get('solarsystemid')

        _ = yield redis.hset('fleet:%s' % fleet.fc, fleet)

        self.event({'action': 'new_fleet', 'fleet': fleet.to_json()})
        self.character.event({'action': 'character_invited_to_fleet',
                              'charname': self.character['charname'],
                              'fleet': fleet.fc.name})


class JoinHandler(BaseHandler):
    @gen.coroutine
    def post(self):
        logger.debug(self.request.arguments)
        fc = yield get_character(self.get_argument('fleet'))
        fleet = fc.fleet
        if fleet is not None:
            if self.character.fleet is not None:
                self.character.add_message('You are already in the fleet.')
                self.send_error(400, reason="You are already in the fleet.")
                raise gen.Return()
            else:
                self.character.fleet = fleet
                self.character.waitlist.clear()
                fleet.queue.append(self.character)
                self.WAITLIST.remove(self.character)
                self.event({'action': 'character_joined_fleet_queue',
                            'charname': self.character['charname'],
                            'fleet': fc.name})
        else:
            self.send_error(400, reason="No such fleet.")


class BaseQueueHandler(BaseHandler):
    status_required = 'queue'


class LeaveHandler(BaseQueueHandler):
    def post(self):
        fleet = self.character.fleet
        fleet.dequeue(self.character)
        self.event({'action': 'character_fleet_changed',
                    'charname': self.character['charname'],
                    'fleet': None})


class TypeHandler(BaseHandler):
    fc_required = True
    def post(self):
        fleet = self.character.fleet
        fleet.fleet_type = self.get_argument('fleet_type')
        self.event({'action': 'fleet_type_changed',
                    'fleet': fleet.fc.name,
                    'fleet_type': fleet.fleet_type})


class DisbandHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):

        fleet = yield get_fleet(self.character.fleet)
        redis.delete(rk_fleet(self.character.fleet))

        self.event({'action': 'del_fleet', 'fleet': self.character.fleet})

        for i in chain(fleet.queue, fleet.members):
            redis.hdel(rk_character(i), 'fleet')
            self.event({'action': 'character_fleet_changed', 'charname': i, 'fleet': None})
            self.add_character_message(i, "Fleet has been disbanded.")


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
        fleet = self.character.fleet
        if fleet is not None:
            character = yield get_character(self.get_argument('character'))
            if character in self.queue:
                self.queue.remove(character)
            self.members.append(character)
            character.fleet = fleet
            character.waitlist = set()
            self.event({'action': 'character_invited_to_fleet',
                        'charname': character['charname'],
                        'fleet': fleet.fc.name})
        else:
            self.send_error(400, reason="You are not in the fleet.")


class DeclineHandler(BaseHandler):
    fc_required = True
    @gen.coroutine
    def post(self):
        character = yield get_character(self.get_argument('character'))
        character.add_message('Вы были исключены из очереди', 'danger')
        character.waitlist = set()
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

            self.ONLINE.add(self.character['charname'])

            self.character.callbacks.append(self.check_events)
            self.USER_CALLBACKS.append(self.check_events)
            if self.character.is_fc:
                self.FC_CALLBACKS.append(self.check_events)

            if native_str(self.get_secure_cookie('uuid')) != self.uuid:
                logger.debug('Character %s has bad uuid cookie',
                             self.character['charname'])
                self.set_secure_cookie('uuid', self.uuid)
                self.add_message('Server has been restarted!')
                self.event({"action": "reload"})
        else:
            self.GUEST_CALLBACKS.append(self.check_events)

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

    def check_events(self):
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
        self.remove_callback()
        self.set_cookie('ts', '%f' % time())
        super(PollHandler, self).finish(events)

    def remove_callback(self):
        if self.character:
            self.USER_CALLBACKS.remove(self.check_events)
            if self.character.is_fc:
                self.FC_CALLBACKS.remove(self.check_events)
            self.character.callbacks.remove(self.event)
            if not self.character.callbacks and self.character['charname'] in self.ONLINE:
                self.ONLINE.remove(self.character['charname'])
        else:
            if self.event in self.GUEST_CALLBACKS:
                self.GUEST_CALLBACKS.remove(self.check_events)

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


MODULE_RE = re.compile('((?P<q>[0-9 ]+)x )?(?P<name>.*)')
DNA_RE = re.compile('fitting:([0-9:;]+::)')


class FitHandler(BaseHandler):

    reload_on_poll = False

    def get(self):
        if self.character.get('fitting'):
            fit = 'fitting:%s' % self.character.get('fitting')
        else:
            fit = ''
        self.render('fit.html', fit=fit)

    @gen.coroutine
    def post(self):

        fit = DNA_RE.search(self.get_argument('dna'))
        if fit is not None:
            fit = fit.group(1)
        else:
            self.character.add_message(
                "DNA substring was not found in your input!"
            )
            self.get()
            raise gen.Return(None)

        self.character['fitting'] = fit

        redis.set(rk_character(self.character['charname']),
                  self.character.get('fitting'))

        e = {
            'action': 'character_fitting_updated',
            'charname': self.character['charname'],
            'ship': get_ship(self.character.get('fitting')),
            'fitting': self.character.get('fitting'),
        }

        self.fc_event(e)
        self.character.event(e)

        self.redirect('/')

    def delete(self):
        redis.hdel(rk_character(self.character['charname']), 'fitting')
        self.get()


class ReadMessageHandler(BaseHandler):
    def post(self):
        uuid = native_str(self.get_argument('uuid'))
        name = self.character['charname']
        redis.lrem(rk_character_ml(name), 1, uuid)
        redis.hdel(rk_character_mh(name), uuid)


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
    (r"/message", ReadMessageHandler),
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
