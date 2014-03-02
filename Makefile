i18n: efq.py templates/*.html
	xgettext --language=Python --keyword=_:1,2 efq.py templates/*.html
	msgmerge i18n/ru_RU/LC_MESSAGES/messages.po messages.po >new.po
	cp new.po i18n/ru_RU/LC_MESSAGES/messages.po
	msgfmt i18n/ru_RU/LC_MESSAGES/messages.po -o i18n/ru_RU/LC_MESSAGES/messages.mo
