from tornado.web import UIModule

class FleetForm(UIModule):
    def render(self, legend, action, submit, fleet=None):
        if fleet is None:
            fleet = {
                'level': None,
                'ts_channel': None,
                'solar_system': '',
            }
        return self.render_string(
            'fleet_form.html',
            legend=legend,
            action=action,
            submit=submit,
            **fleet
        )
