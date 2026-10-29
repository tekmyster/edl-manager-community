import pytest
@pytest.fixture(autouse=True)
def legacy_aggregation_only_head(request,monkeypatch):
    if request.module.__name__ not in ('test_native_ingestion_partitions','test_rolling_liveness'):return
    import native_ingestion as n
    original=n.head_page
    def head(store,session,*args,**kwargs):
        class EmptyHead:
            def post(self,*a,**k):
                from test_native_ingestion_partitions import Response
                return Response({'_shards':{'total':1,'failed':0},'hits':{'hits':[]}})
        return original(store,EmptyHead(),*args,**kwargs)
    monkeypatch.setattr(n,'head_page',head)
