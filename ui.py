# coding: utf-8

from tornado.web import UIModule


class Fit(UIModule):
    def render(self, character):
        return self.render_string('m_fit.html', character=character)
