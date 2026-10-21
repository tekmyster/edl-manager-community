
CREATE TABLE IF NOT EXISTS pipeline_schema(id INTEGER PRIMARY KEY CHECK(id=1),version INTEGER NOT NULL);
INSERT OR IGNORE INTO pipeline_schema VALUES(1,1);
CREATE TABLE IF NOT EXISTS pipeline_plans(id TEXT PRIMARY KEY,packet TEXT NOT NULL,config TEXT NOT NULL,input_key TEXT NOT NULL,owner TEXT NOT NULL,process TEXT NOT NULL,state TEXT NOT NULL,created TEXT NOT NULL,deadline REAL NOT NULL,assessment TEXT NOT NULL UNIQUE,outcome TEXT,provider TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS pipeline_packet ON pipeline_plans(packet,config,created);
CREATE INDEX IF NOT EXISTS pipeline_compaction ON pipeline_plans(created,id) WHERE outcome IS NOT NULL AND state IN ('completed','failed');
CREATE TABLE IF NOT EXISTS pipeline_stages(parent TEXT NOT NULL,ordinal INTEGER NOT NULL CHECK(ordinal IN(1,2)),request_id TEXT NOT NULL UNIQUE,request_hash TEXT,state TEXT NOT NULL,charged_day TEXT,entered TEXT,receipt TEXT,metadata TEXT,PRIMARY KEY(parent,ordinal));
CREATE TABLE IF NOT EXISTS pipeline_reservations(parent TEXT PRIMARY KEY,day TEXT NOT NULL,held INTEGER NOT NULL CHECK(held BETWEEN 0 AND 2));
CREATE INDEX IF NOT EXISTS pipeline_reserved_day ON pipeline_reservations(day,held);
CREATE TABLE IF NOT EXISTS pipeline_active(slot INTEGER PRIMARY KEY CHECK(slot=1),parent TEXT NOT NULL UNIQUE);
