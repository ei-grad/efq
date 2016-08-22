#!/usr/bin/env python

from datetime import datetime
from os import environ as env
from urllib.parse import urlencode, urlparse, urljoin
import binascii
import os

from requests.auth import HTTPBasicAuth
import requests

from flask import Flask, request, session
from flask import abort, redirect, render_template, url_for

from flask_sqlalchemy import SQLAlchemy

from flask_login import LoginManager, UserMixin, login_user, current_user
from flask_login import login_required


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = env.get('SQLALCHEMY_DATABASE_URI', 'sqlite://efq.sqlite3')
db = SQLAlchemy(app)


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth_login"


@login_manager.user_loader
def load_user(user_id):
    return Character.query.get(user_id)


class Character(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True)
    is_active = db.Column(db.Boolean())


class Fleet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    fleet_type = db.Column(db.String(2))
    is_active = db.Column(db.Boolean())
    commander_id = db.Column(db.Integer, db.ForeignKey(Character.id), index=True)

    commander = db.relationship(Character, lazy='joined')


class Journal(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    fleet_id = db.Column(db.Integer, db.ForeignKey(Fleet.id), index=True)
    character_id = db.Column(db.Integer, db.ForeignKey(Character.id), index=True)
    state = db.Column(db.String(16))
    comment = db.Column(db.Text())

    fleet = db.relationship(Fleet)
    character = db.relationship(Character)


class Queue(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, index=True)
    fleet_id = db.Column(db.Integer, db.ForeignKey(Fleet.id), index=True)
    character_id = db.Column(db.Integer, db.ForeignKey(Character.id), index=True)
    state = db.Column(db.String(16))

    fleet = db.relationship(Fleet)
    character = db.relationship(Character)

    __table_args__ = (
        db.UniqueConstraint('fleet_id', 'character_id',
                            name='uniq_queue_fleet_character'),
    )


@app.route("/")
def home():
    fleets = Fleet.query.filter_by(is_active=True)
    return render_template(
        "index.html",
        vg_fleets=[i for i in fleets if i.fleet_type == 'VG'],
        hq_fleets=[i for i in fleets if i.fleet_type == 'HQ'],
    )


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return (
        test_url.scheme in ('http', 'https')
        and
        ref_url.netloc == test_url.netloc
    )


def set_return_url(return_url):
    if not is_safe_url(return_url):
        abort(400, 'Bad return_url!')
    session['return_url'] = return_url


@app.route("/auth/login")
def auth_login():

    session['oauth_state'] = binascii.b2a_hex(os.urandom(8))

    if 'return_url' in request.args:
        set_return_url(request.args['return_url'])

    return redirect(
        'https://login.eveonline.com/oauth/authorize/?' + urlencode({
            'response_type':
            'code',
            'redirect_uri': url_for('auth_callback', _external=True),
            'client_id': env['EFQ_CLIENT_ID'],
            'scope': ' '.join([
                'characterLocationRead',
                'characterSkillsRead',
                'fleetRead',
                'fleetWrite',
                'publicData',
            ]),
            'state': session['oauth_state'],
        })
    )


@app.route("/auth/callback")
def auth_callback():

    state = request.args.get('state')
    expected_state = session.pop('oauth_state')
    if state != expected_state:
        app.logger.error("Bad OAuth state %s (expected %s)",
                         state, expected_state)
        abort(400, 'Bad OAuth "state" value!')

    code = request.args.get('code')

    token = requests.post(
        'https://login.eveonline.com/oauth/token',
        auth=HTTPBasicAuth(env['EFQ_CLIENT_ID'], env['EFQ_CLIENT_SECRET']),
        params={
            'grant_type': 'authorization_code',
            'code': code,
        }
    ).json()
    info = requests.post(
        'https://login.eveonline.com/oauth/verify',
        headers={'Authorization': 'Bearer %s' % token['access_token']},
    ).json()
    login_user(info['CharacterID'])
    return redirect(session.pop("return_url", "/"))


@app.route("/fleet/<int:fleet_id>/queue")
def fleet_queue(fleet_id):
    fleet = Fleet.query.get_or_404(fleet_id)
    queue = Queue.query.filter(
        Queue.fleet == fleet,
        Queue.state == 'WAITING',
    ).order_by(
        Queue.timestamp
    ).options(
        db.joinedload(Character)
    )
    return render_template("queue.html", fleet=fleet, queue=queue)


@app.route("/fleet/<int:fleet_id>/wait")
@login_required
def fleet_wait(fleet_id):
    state = get_state(fleet_id, current_user)
    if state.state == 'ACTIVE':
        return redirect(url_for("fleet", fleet_id=state.fleet.id))
    if request.method == 'POST':
        transition(state, 'WAITING')
    fleet = state.fleet
    members = Queue.query.filter_by(fleet=fleet, state='ACTIVE')
    queue = Queue.query.filter_by(fleet=fleet, state='WAITING')
    return render_template(
        "wait.html", state=state, fleet=fleet, members=members, queue=queue,
    )


@app.route("/fleet/<int:fleet_id>/invite/<int:character_id>", methods=["POST"])
@login_required
def fleet_invite(fleet_id, character_id):
    fleet = Fleet.query.get_or_404(fleet_id)
    character = Character.query.get_or_404(character_id)
    if current_user != fleet.commander:
        app.logger.warning("%s tried to invite %s to fleet %s but its FC is %s",
                           current_user.name, character.name, fleet.id,
                           fleet.commander.name)
        abort(403, "You are not allowed to invite pilots to %s fleet!" % fleet.commander.name)
    state = Queue.query.filter_by(
        fleet=fleet,
        character=character
    ).scalar()
    transition(state, 'ACTIVE')
    return redirect(request.args.get(
        'return_url', url_for('fleet', fleet_id=fleet.id)
    ))


def get_state(fleet_id, character):
    fleet = Fleet.query.get_or_404(fleet_id)
    state = Queue.query.filter_by(
        fleet=fleet,
        character=character,
    ).scalar()
    if state is None:
        state = Queue(
            timestamp=datetime.now(),
            fleet=fleet,
            character=current_user,
        )
    return state


def transition(state, to_state, comment=None):
    state.timestamp = datetime.now()
    state.state = to_state
    db.add(state)
    db.add(Journal(
        fleet=state.fleet,
        character=state.character,
        timestamp=state.timestamp,
        state=state.state,
        comment=comment,
    ))
    db.commit()
