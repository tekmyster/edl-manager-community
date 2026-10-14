from werkzeug.datastructures import MultiDict
from app import browse_table
from table_filters import highlight
from violator_times import format_time
from test_ui_settings import ui

def test_highlights_are_literal_case_insensitive_and_html_escaped():
 table={'state':{'f_enrichment':'scanner'},'prefix':'','choices':{},'dates':set()}
 rendered=str(highlight('<img onerror=alert(1)> SCANNER scanner',table,'enrichment'))
 assert '<img' not in rendered and '&lt;img' in rendered
 assert rendered.count('<mark')==2 and '>SCANNER</mark>' in rendered
 table['state']['f_enrichment']='.*'
 assert '<mark' not in str(highlight('scanner',table,'enrichment'))
 assert '<mark' in str(highlight('8.8.8.8',table,'ip','8.8'))

def test_calendar_days_ranges_timezone_boundaries_and_port_membership():
 rows=[{'ip':'a','seen':'2026-01-02T04:59:59+00:00','ports':[22,443]}, {'ip':'b','seen':'2026-01-02T05:00:00+00:00','ports':[2222]}, {'ip':'c','seen':None,'ports':[]}]
 columns={'seen':('Seen',lambda r:format_time(r['seen'],'America/New_York'),lambda r:r['seen'] or ''),'ports':('Ports',lambda r:str(r['ports']),lambda r:tuple(r['ports']))}
 def table(**args):return browse_table(rows,MultiDict(args),'',columns,'ports')
 assert [r['ip'] for r in table(f_seen='2026-01-01')['rows']]==['a']
 assert {r['ip'] for r in table(f_seen_from='2026-01-01',f_seen_to='2026-01-02')['rows']}=={'a','b'}
 assert table(f_seen_from='2026-01-03',f_seen_to='2026-01-01')['total']==0
 assert table(f_seen='invalid')['total']==0
 assert [r['ip'] for r in table(f_ports='22')['rows']]==['a']
 assert table()['choices']['ports']==[('22','22'),('443','443'),('2222','2222')]
 single={'port':('Port',lambda r:str(r['port']),lambda r:r['port'])}
 result=browse_table([{'port':443},{'port':1443}],MultiDict({'f_port':'443'}),'a_',single,'port')
 # Prefix-aware filter still matches one complete port.
 result=browse_table([{'port':443},{'port':1443}],MultiDict({'a_f_port':'443'}),'a_',single,'port')
 assert result['total']==1

def test_ui_calendar_dropdown_and_escaped_highlighting(ui):
 app,c,cfg=ui
 app.store.add_rule('block','8.8.8.8','Ticket <script>alert(1)</script>',None,'admin')
 html=c.get('/?f_ip=8.8',base_url='https://localhost').text
 assert '<mark class="filter-match">8.8</mark>' in html and 'href="/ip/8.8.8.8"' in html
 assert 'type="date" name="f_first_seen"' in html
 assert 'name="f_first_seen_from"' in html and '<select form="evidence-filters" id="filter-ports"' in html
 html=c.get('/results/blacklisted?m_f_reason=Ticket',base_url='https://localhost').text
 assert '<mark class="filter-match">Ticket</mark>' in html and '<script>alert(1)</script>' not in html
