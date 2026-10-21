"""Direct purposes choose fixed claims; removed rationale payloads cannot pass."""
import copy,json,pytest
import behavior_ai as ai
import behavior_generation as gen
from test_source_observations import linked_packet
from test_generation_choices import transport

@pytest.mark.parametrize('purpose',['omit','detail','support'])
def test_structured_purpose_preserves_complete_statement_and_no_authored_text(purpose):
 packet=linked_packet();tables,_=gen.offers(packet,[],{});key=next(iter(tables['facts']));wire=gen.example(packet);wire['observations']={key:{**wire['observations'][key],'purpose':purpose}};before=copy.deepcopy(wire)
 value=transport(packet,wire)[0][0]
 assert wire==before and value['findings']==([] if purpose=='omit' else [tables['facts'][key]])
 assert 'reason' not in json.dumps(value)

@pytest.mark.parametrize('bad',[{},[],None,True,{'purpose':'detail'},{'reason':'private','purpose':'detail'},['detail','support'],'finding','not-offered'])
def test_removed_reviews_and_conflicting_roles_reject_without_repair(bad):
 packet=linked_packet();wire=gen.example(packet);key=next(iter(wire['observations']));wire['observations']={key:bad};before=copy.deepcopy(wire)
 with pytest.raises(ai.ModelOutputError) as caught:transport(packet,wire)
 assert before==wire and 'private' not in json.dumps(caught.value.metadata)

def test_duplicate_keys_reject_before_one_role_can_replace_another():
 with pytest.raises(gen.ChoiceError):gen.parse_wire('{"observations":{"x":"detail","x":"counterevidence"}}')

@pytest.mark.parametrize('classification',['malicious','benign'])
def test_purpose_never_creates_missing_support(classification):
 packet=linked_packet();wire=gen.example(packet);wire['classification']=classification
 with pytest.raises(ai.ModelOutputError):transport(packet,wire)

@pytest.mark.parametrize('version',['grounded-groups-12','joint-keyed-purpose-1'])
def test_legacy_nested_reviews_reject_even_with_new_marker(version):
 packet=linked_packet();wire=gen.example(packet);wire['generation_schema_version']=version;wire['observations']={k:{'reason':'untrusted','purpose':v} for k,v in wire['observations'].items()}
 with pytest.raises(ai.ModelOutputError):transport(packet,wire)
