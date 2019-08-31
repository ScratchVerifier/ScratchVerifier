import sys
import os
import re
import json

with open(os.path.join(os.path.dirname(__file__), 'docs.json')) as f:
    DATA = json.load(f)

class Things:
    @classmethod
    def _items(cls, things, elem):
        for i in things:
            if isinstance(i, str):
                print('<{0}>{1}</{0}>'.format(elem, i))
                continue
            getattr(cls, i['type'])(i)

    @classmethod
    def _id(cls, name, sub):
        nam = name.lower().replace(' ', '-')
        sub.append({
            "id": nam,
            "name": name,
            '*': []
        })
        return nam

    @classmethod
    def intro(cls, thing):
        print('<h1 id="{}">{}</h1>'.format(
            cls._id(thing['title'], contents),
            thing['title']
        ))
        cls._items(thing['paragraphs'], 'p')

    @classmethod
    def section(cls, thing):
        print('<h2 id="{}">{}</h2>'.format(
            cls._id(thing['heading'], contents[-1]['*']),
            thing['heading']
        ))
        cls._items(thing['paragraphs'], 'p')

    @classmethod
    def endpoint(cls, thing):
        print('<h3 id="{}">{} Endpoint</h3>'.format(
            cls._id(thing['name'] + ' Endpoint', contents[-1]['*'][-1]['*']),
            thing['name']
        ))
        print('<p>%s</p>' % thing['desc'])
        print('<div class="endpoint">')
        path = thing['path']
        has_query = False
        has_param = False
        for i in thing['params']:
            has_param = True
            if thing['params'][i]['query']:
                has_query = True
                continue
            path = path.replace('{%s}' % i, '<span class="param">{%s}</span>' % i)
        print('<div class="method-path{}" onclick="showOrHide(this)"><span \
class="method">{}</span> <code>{}</code> <a href=\"#authorization\"><img \
src="https://image.flaticon.com/icons/png/512/61/61457.png" \
title="Authorization necessary" /></a></div>'.format(
            " auth-needed" if 'auth' in thing else '',
            thing['method'],
            path
        ))
        print('<div style="display: none">')
        if has_param:
            print("""<table><caption>URL Params</caption>
<tr><th>Field</th><th>Type</th><th>Description</th>""")
            for k, v in thing['params'].items():
                if v['query']:
                    continue
                print('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                    k, v['type'], v['desc']
                ))
            print('</table>')
        if has_query:
            print("""<table><caption>Query String Params</caption>
<tr><th>Field</th><th>Type</th><th>Description</th>""")
            for k, v in thing['params'].items():
                if not v['query']:
                    continue
                print('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                    k, v['type'], v['desc']
                ))
            print('</table>')
        print("""<table><caption>HTTP statuses</caption>
<tr><th>Status</th><th>Meaning</th>""")
        for k, v in thing['http'].items():
            print('<tr><td>{}</td><td>{}</td></tr>'.format(k, v))
        print('</table>')
        new_thing = {}
        new_thing['heading'] = 'Returns '
        if thing['returns']:
            name = thing['returns']['type']
            if thing['returns']['type'].endswith('[]'):
                name = name[:-2]
                new_thing['heading'] += 'a list of <a href=\"#{}-object\">\
{}</a> objects'.format(name.lower(), name)
            else:
                new_thing['heading'] += 'a <a href=\"#{}-object\">{}</a> \
object'.format(
                    name.lower(), name
                )
            del thing['returns']['type']
            new_thing['text'] = json.dumps(thing['returns'], indent=2)
        else:
            new_thing['heading'] += 'nothing'
            new_thing['text'] = ''
        cls.headedpre(new_thing)
        print('</div></div>')

    @classmethod
    def object(cls, thing):
        print('<h3 id="{}">{} Object</h3>'.format(
            cls._id(thing['name'] + ' Object', contents[-1]['*'][-1]['*']),
            thing['name']
        ))
        print('<p>{}</p>'.format(thing['desc']))
        print("""<table><caption>{} Structure</caption>
<tr><th>Field</th><th>Type</th><th>Description</th></tr>
""".format(thing['name']))
        for k, v in thing['fields'].items():
            print('<tr><td>{}</td><td>{}</td><td>{}</td></tr>'.format(
                k, v['type'], v['desc']
            ))
        print('</table>')

    @classmethod
    def headedpre(cls, thing):
        print('<table><caption>{}</caption>'.format(thing['heading']))
        print('<tr><td class="pre">{}</td></tr>'.format(thing['text']))
        print('</table>')

    @classmethod
    def ol(cls, thing):
        print('<ol>')
        cls._items(thing['items'], 'li')
        print('</ol>')

    @classmethod
    def ul(cls, thing):
        print('<ul>')
        cls._items(thing['items'], 'li')
        print('</ul>')

def conts(sub):
    sub['name'] = sub['name'].replace(' ', '&nbsp;')
    print('<div><a href="#{id}">{name}</a>'.format(**sub))
    print('<ul>')
    for i in sub['*']:
        print('<li>')
        conts(i)
        print('</li>')
    print('</ul>')

links = {}
for filename, data in DATA.items():
    name = data[0]['title'].replace(' ', '&nbsp;')
    links[filename] = '<div><a href="{}">{}</a></div>'.format(filename, name)

for filename, data in DATA.items():
    file = open(filename, 'w')
    sys.stdout = file
    contents = []
    print("""<!doctype html>
<html>
<head>
    <link rel="stylesheet" href="main.css" />
    <script src="main.js"></script>
    <script>
    if (location.pathname === "/docs"){location.pathname = "/docs/"};
    </script>
    <title>%s</title>
</head>
<body><div id="body">
""" % (data[0]['title'] + ' - ScratchVerifier Documentation'))
    for thing in data:
        getattr(Things, thing['type'])(thing)
    print('</div><div id="contents"><h1>Navigation</h1>')
    for i in contents:
        conts(i)
    for fname, link in links.items():
        if filename == fname:
            continue
        print(link)
    print("""</div></body>
</html>""")
    file.close()
