"""Offline hard-deadline, cancellation and production HTTPS transport tests."""
import json,threading,time
import pytest
from behavior_deadline import Deadline,Expired,Cancelled,post

@pytest.mark.parametrize('seconds',[10,120,180])
def test_shared_remaining_time_with_fake_clock(seconds):
 clock=[0.0];d=Deadline(seconds,clock=lambda:clock[0])
 try:
  clock[0]=seconds*.7;assert d.left()==pytest.approx(seconds*.3)
  clock[0]=seconds;assert pytest.raises(Expired,d.check)
 finally:d.finish()

def test_blocking_admission_returns_at_deadline_and_discards_late_reply():
 entered=threading.Event();release=threading.Event();closed=threading.Event()
 class Result:
  def close(self):closed.set()
 def blocked():entered.set();release.wait(2);return Result()
 d=Deadline(.12);start=time.monotonic()
 try:
  with pytest.raises(Expired):d.call(blocked)
  assert entered.is_set() and time.monotonic()-start<.7
 finally:d.finish();release.set()
 assert closed.wait(1)

@pytest.mark.parametrize('mode',['trickle','blocked'])
def test_trickle_and_blocked_body_cannot_extend_deadline(mode):
 released=threading.Event();closed=threading.Event()
 class Reply:
  def iter_content(self,n):
   if mode=='blocked':released.wait(2)
   else:
    while not released.wait(.015):yield b'x'
  def close(self):closed.set();released.set()
 d=Deadline(.12);start=time.monotonic()
 try:
  with pytest.raises(Expired):list(d.chunks(Reply()))
  assert time.monotonic()-start<.7 and closed.wait(.5)
 finally:d.finish();released.set()

def test_cancel_stops_blocked_io():
 stop=threading.Event();d=Deadline(120,stop.is_set)
 threading.Timer(.05,stop.set).start();start=time.monotonic()
 try:
  with pytest.raises(Cancelled):d.call(lambda:time.sleep(.5))
  assert time.monotonic()-start<.5
 finally:d.finish()

def test_production_transport_has_one_post_and_remaining_timeout(monkeypatch):
 events=[];clock=[0.0]
 class Sock:
  def settimeout(self,n):events.append(('timeout',n))
  def shutdown(self,n):pass
  def close(self):pass
 class Raw:
  status=200
  def read1(self,n):return b''
  def close(self):pass
 class Connection:
  def __init__(self,host,port,timeout,context):self.sock=Sock();events.append(('connect_timeout',timeout))
  def connect(self):clock[0]=12
  def request(self,method,path,body,headers):events.append((method,path,json.loads(body),headers));clock[0]=25
  def getresponse(self):return Raw()
  def close(self):pass
 monkeypatch.setattr('behavior_deadline.http.client.HTTPSConnection',Connection)
 monkeypatch.setattr('behavior_deadline.ssl.create_default_context',lambda **kw:object())
 d=Deadline(180,clock=lambda:clock[0])
 try:
  r=post('https://127.0.0.1:443/api/chat',{'Authorization':'Bearer synthetic'},json={'x':1},verify=True,deadline=d,admission=True)
  assert r.status_code==200 and [e[0] for e in events].count('POST')==1
  assert [e[1] for e in events if e[0]=='timeout']==[168,155]
  assert [e for e in events if e[0]=='POST'][0][3]['X-EDL-Admission-Wait']=='15'
 finally:d.finish()
