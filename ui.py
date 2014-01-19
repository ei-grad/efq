# coding: utf-8

from tornado.web import UIModule


FLEET_TYPES = ['Vanguard (10)', 'Assault (20)', 'HQ (40)']


class FakeFleet(object):
    def __init__(self):
        self.fleet_type = None


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
        )
