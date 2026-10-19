# Exact indexed function from the pre-repair source_handoff module.
def indexed(brain,address,revision,source_cfg=None):
 from evidence_history import collection_scope
 with brain.connect() as db:db.execute('DELETE FROM source_sample_ready WHERE ip=? AND scope=? AND revision=?',(address,collection_scope(brain,source_cfg),revision))
