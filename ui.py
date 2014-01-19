# coding: utf-8

from tornado.web import UIModule


FLEET_TYPES = ['Vanguard (10)', 'Assault (20)', 'HQ (40)']

TS_CHANNELS = [
    'Shield-Флот 1',
    'Shield-Флот 2',
    'Shield-Флот 3',
    'Shield-Флот 4',
    'Shield-Флот 5',
    'Armor-Флот 1',
    'Armor-Флот 2',
    'PvP-Флот 1',
]


class FakeFleet(object):
    def __init__(self):
        self.level = None
        self.ts_channel = None
        self.solar_system = ''


class FleetForm(UIModule):
    def render(self, legend, action, submit, fleet=None):
        if fleet is None:
            fleet = FakeFleet()
        return self.render_string(
            'fleet_form.html',
            legend=legend,
            action=action,
            submit=submit,
            fleet=fleet,
            FLEET_TYPES=FLEET_TYPES,
            TS_CHANNELS=TS_CHANNELS,
        )
