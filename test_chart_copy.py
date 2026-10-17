"""Default chart copy contract, useful disclosure and keyboard data alternatives."""
import datetime as dt
import json
import re
from html.parser import HTMLParser
from flask import render_template
from behavior_ai import Brain
from production_analytics import summary
from test_ui_settings import ui


class Node:
    def __init__(self,tag='',attrs=(),parent=None):self.tag=tag;self.attrs=dict(attrs);self.parent=parent;self.children=[]
    def text(self,visible=True):
        if visible and (self.tag in ('svg','script','style','title','head') or 'hidden' in self.attrs or 'info-bubble' in self.attrs.get('class','').split()):return ''
        children=self.children
        if visible and self.tag=='details' and 'open' not in self.attrs:children=[c for c in children if isinstance(c,Node) and c.tag=='summary']
        return ' '.join(c.text(visible) if isinstance(c,Node) else c for c in children)
    def walk(self):
        yield self
        for c in self.children:
            if isinstance(c,Node):yield from c.walk()
    def exposed(self):
        p=self
        while p:
            if 'info-bubble' in p.attrs.get('class','').split() or 'hidden' in p.attrs or p.tag in ('svg','script','style','head'):return False
            if p.tag=='details' and 'open' not in p.attrs:return False
            p=p.parent
        return True


class Page(HTMLParser):
    def __init__(self,html):super().__init__();self.root=Node();self.stack=[self.root];self.feed(html)
    def handle_starttag(self,tag,attrs):
        n=Node(tag,attrs,self.stack[-1]);self.stack[-1].children.append(n)
        if tag not in ('meta','link','input','img','br','hr','source'):self.stack.append(n)
    def handle_startendtag(self,tag,attrs):self.handle_starttag(tag,attrs);self.handle_endtag(tag)
    def handle_endtag(self,tag):
        for i in range(len(self.stack)-1,0,-1):
            if self.stack[i].tag==tag:self.stack=self.stack[:i];break
    def handle_data(self,data):self.stack[-1].children.append(data)


def fetch(client,route):
    r=client.get(route,base_url='https://localhost');assert r.status_code==200
    return Page(r.text)


def test_default_chart_surfaces_are_concise_and_methodology_remains_disclosed(ui):
    app,c,_=ui
    for route in ('/','/analytics','/behavior/metrics'):
        page=fetch(c,route)
        scope=next(n for n in page.root.walk() if n.attrs.get('id')==('ai-operations' if route=='/' else 'main-content'))
        paragraphs=[n.text() for n in scope.walk() if n.tag in ('p','caption') and n.exposed()]
        assert all(len(re.findall(r'\S+',p))<=22 for p in paragraphs),paragraphs
        assert all(not n.text().strip() for n in scope.walk() if 'ops-hover' in n.attrs.get('class','').split())
        # All long methods live behind a keyboard-operable closed help disclosure.
        methods=[n for n in scope.walk() if 'info-bubble' in n.attrs.get('class','').split()]
        assert methods and all(n.parent.tag=='details' and 'open' not in n.parent.attrs for n in methods)
        assert all(n.attrs.get('tabindex')=='0' for n in methods if 'chart-help' in n.parent.attrs.get('class',''))
        text=' '.join(n.text(False) for n in methods).lower()
        if route in ('/','/analytics'):assert 'final-only' in text and 'partial reports' in text
        if route=='/analytics':
            assert 'hit ratio' in text and '20 indicator ids' in text and 'reviewer-attested' in text
            assert 'nat' in text and '35 days' in text
            assert 'Overall usefulness: unavailable' in scope.text()
            assert 'partial' in scope.text().lower() and 'uncollected' in scope.text().lower()
        if route=='/behavior/metrics':assert 'full request' in text and 'not establish accuracy' in text


def test_first_content_unknowns_and_read_failures_remain_visible(ui):
    app,_,_=ui
    with app.test_request_context('/'):
        none=Page(render_template('analytics_tiles.html',analytics=None));assert 'AI measurements unavailable' in none.root.text()
        data=summary(Brain(app.store));data['error']=True
        page=Page(render_template('analytics_tiles.html',analytics=data))
        assert 'Some measurements unavailable' in page.root.text()
        assert page.root.text().count('Unavailable')>=3
        assert 'Partial history' in page.root.text()
        assert any(n.attrs.get('role')=='alert' and n.exposed() for n in page.root.walk())


def test_performance_intervals_keep_keyboard_values_units_and_equivalent_table(ui):
    app,c,_=ui;brain=Brain(app.store);at=dt.datetime.now(dt.timezone.utc)-dt.timedelta(minutes=5)
    with brain.connect() as db:
        db.execute('INSERT INTO assessments VALUES(?,?,?,?,?,?,?,?,?)',('copy-fixture','packet','cfg',at.isoformat(),at.isoformat(),'completed',json.dumps({'classification':'inconclusive','metadata':{'input_tokens':11,'output_tokens':7}}),'',3))
    page=fetch(c,'/behavior/metrics');points=[n for n in page.root.walk() if n.attrs.get('data-tip')]
    assert len(points)==96 and all(n.attrs.get('tabindex')=='0' and n.attrs.get('role')=='img' for n in points)
    assert any('Input 11; output 7 tokens' in n.attrs['data-tip'] for n in points)
    assert any('Mean full response 3.0 seconds' in n.attrs['data-tip'] for n in points)
    assert any('Unavailable' in n.attrs['data-tip'] for n in points)
    table=next(n for n in page.root.walk() if n.attrs.get('id')=='metrics-intervals')
    assert len([n for n in table.walk() if n.tag=='tr'])==25
    assert '11' in table.text(False) and '7' in table.text(False)
    assert any(n.tag=='a' and n.attrs.get('href')=='#metrics-intervals' for n in page.root.walk())
    assert any(n.tag=='script' and 'v=20261017-3' in n.attrs.get('src','') for n in page.root.walk())
