# coding: utf-8

from tornado.web import UIModule


class Fit(UIModule):
    def render(self, character, edit=False):
        return self.render_string('m_fit.html', character=character, edit=edit)


class Character(UIModule):
    def render(self, character):
        return '<a href="javascript:CCPEVE.showInfo(1377, %s)">%s</a>' % (
            character.charid, character.charname.replace(' ', '&nbsp;')
        )
