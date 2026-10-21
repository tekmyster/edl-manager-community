"""Source row packing pays for optional accounts without filtering source data."""
import copy
import pytest
import behavior_representation as rep


def sample():
 rows=[{'id':'first','value':None,'unknown':{'symbol_ref':'literal'},'array':[1,True,'~0']},{'value':'same text','id':'later','extra':{'record_paths':'literal'},'empty':[]}]
 return {'packet':{'events':rows,'context':[{'provider':'untrusted','object_literal':[['literal',False]]}]},'candidates':[{'current_events':[{'packet_event_ref':'first'}],'historical_events':copy.deepcopy(rows)}],'offered':{'facts':{'fact':{'summary':'literal statement','evidence_ids':['first']}}}}


def test_roundtrip_retains_order_unknown_fields_markers_nulls_types_and_candidates():
 value=sample();before=copy.deepcopy(value);wire=rep.factor_selection(value)
 assert wire['record_paths']==[['packet','events'],['packet','context'],['candidates',0,'current_events'],['candidates',0,'historical_events']]
 assert rep.expand(wire)==value==before
 assert list(rep.expand(wire)['packet']['events'][1])==list(value['packet']['events'][1])


@pytest.mark.parametrize('row',[[-1], [True], [999], [0], [0,'extra','fields','bad','count','extra-value']])
def test_invalid_source_shape_or_field_count_rejects(row):
 wire=rep.factor_selection(sample());wire['input']['packet']['events'][0]=row
 with pytest.raises(ValueError):rep.expand(wire)


def test_mixed_nonrecord_array_is_not_interpreted_as_packed_source_rows():
 value=sample();value['packet']['events'].append(['literal','row'])
 wire=rep.factor_selection(value);assert ['packet','events'] not in wire['record_paths']
 assert rep.expand(wire)==value


def test_field_name_packing_reduces_repetition_without_dropping_any_value():
 rows=[{'event_id':str(i),'source':'same source','sensor':'same sensor','untrusted_extra_field':{'nullable':None,'content':'data'}} for i in range(10)]
 value={'packet':{'events':rows}};wire=rep.factor_selection(value)
 assert len(wire['record_shapes'])==1 and rep.expand(wire)==value
 assert len(rep.compact(wire))<len(rep.compact(rep.factor(value)))
