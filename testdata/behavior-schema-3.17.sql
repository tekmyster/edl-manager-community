
CREATE TABLE IF NOT EXISTS publication_samples(created TEXT PRIMARY KEY,points REAL NOT NULL,adjusted INTEGER NOT NULL,blocks INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS analysis_counters(hour TEXT NOT NULL,kind TEXT NOT NULL,count INTEGER NOT NULL,PRIMARY KEY(hour,kind));
CREATE TABLE IF NOT EXISTS packets(id TEXT PRIMARY KEY,ip TEXT NOT NULL,created TEXT NOT NULL,content TEXT NOT NULL,features TEXT NOT NULL,baseline INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS packets_ip ON packets(ip,created);
CREATE TABLE IF NOT EXISTS current_packets(ip TEXT PRIMARY KEY,packet_id TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS packet_feature_index(feature TEXT NOT NULL,packet_id TEXT NOT NULL,PRIMARY KEY(feature,packet_id));
CREATE INDEX IF NOT EXISTS packet_feature_packet ON packet_feature_index(packet_id);
CREATE TABLE IF NOT EXISTS packet_feature_ready(packet_id TEXT PRIMARY KEY);
CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,packet_id TEXT NOT NULL,config_id TEXT NOT NULL,created TEXT NOT NULL,expires TEXT NOT NULL,status TEXT NOT NULL,result TEXT NOT NULL,error TEXT NOT NULL,latency REAL NOT NULL);
CREATE INDEX IF NOT EXISTS assessments_packet ON assessments(packet_id,config_id,created);
CREATE INDEX IF NOT EXISTS assessments_created ON assessments(created);
CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY,packet_id TEXT NOT NULL,config_id TEXT NOT NULL,state TEXT NOT NULL,lease REAL NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,updated TEXT NOT NULL,UNIQUE(packet_id,config_id));
CREATE TABLE IF NOT EXISTS usage(day TEXT PRIMARY KEY,requests INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS links(id TEXT PRIMARY KEY,left_packet TEXT NOT NULL,right_packet TEXT NOT NULL,similarity REAL NOT NULL,common TEXT NOT NULL,state TEXT NOT NULL,created TEXT NOT NULL,UNIQUE(left_packet,right_packet));
CREATE TABLE IF NOT EXISTS reviews(id TEXT PRIMARY KEY,target TEXT NOT NULL,outcome TEXT NOT NULL,notes TEXT NOT NULL,actor TEXT NOT NULL,created TEXT NOT NULL);
