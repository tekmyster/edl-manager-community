<?php
/** Native local MISP import of prevalidated, context-only IP snapshots. */
App::uses('AppShell', 'Console/Command');
class MispManagedFeedShell extends AppShell {
    public function main() {
        Configure::write('MISP.background_jobs', false);
        Configure::write('MISP.disable_emailing', true);
        // Optional compatibility for an existing passwordless Redis, this process only.
        if (isset($this->args[2]) && $this->args[2] === 'redis-no-password') {
            Configure::write('MISP.redis_password', '');
            Configure::write('SimpleBackgroundJobs.redis_password', '');
        }
        $this->loadModel('Feed'); $this->loadModel('Event');
        $this->loadModel('MispAttribute'); $this->loadModel('Warninglist'); $this->loadModel('User');
        if (empty($this->args[0])) throw new Exception('Snapshot status file required');
        $statusPath = realpath($this->args[0]);
        $base = realpath(APP . 'tmp/managed-ip-context');
        if (!$base || !$statusPath || strpos($statusPath, $base . DIRECTORY_SEPARATOR) !== 0) throw new Exception('Snapshot outside managed local scope');
        $status = json_decode(file_get_contents($statusPath), true);
        if (!is_array($status) || !isset($status['sources']) || $status['distribution'] !== 0 || $status['to_ids'] !== false) throw new Exception('Invalid local snapshot metadata');
        $roles = $this->User->Role->find('list', array('conditions'=>array('perm_site_admin'=>1), 'fields'=>array('id','id')));
        $account = $this->User->find('first', array('conditions'=>array('role_id'=>array_values($roles)), 'recursive'=>-1));
        if (!$account) throw new Exception('Existing local administrator required');
        $user = $this->User->getAuthUser($account['User']['id']);
        $org = $this->User->Organisation->find('first', array('conditions'=>array('Organisation.id'=>$user['org_id']), 'recursive'=>-1));
        if (!$org) throw new Exception('Existing local organisation required');
        $a = $this->MispAttribute->alias;
        $recentConditions = array($a.'.deleted'=>false, $a.'.type'=>array('ip-src','ip-dst','ip-src|port','ip-dst|port'), $a.'.timestamp >='=>time()-30*86400);
        $recent = $this->MispAttribute->find('count', array('recursive'=>-1,'conditions'=>$recentConditions));
        $projected = $recent;
        $prepared = array();
        foreach ($status['sources'] as $source) {
            if (!in_array($source['status'], array('ok','healthy_empty','held_last_good','unavailable','expired_revoke'), true)) throw new Exception('Unknown source state');
            if (in_array($source['status'], array('ok','healthy_empty','held_last_good'), true) && strtotime($source['expires']) <= time()) throw new Exception('Staged source expired; restage before import');
            if (!preg_match('/^[a-z0-9_-]{1,64}$/D', $source['id'])) throw new Exception('Invalid source identifier');
            $folder = realpath($base . DIRECTORY_SEPARATOR . $source['id']);
            if (!$folder || strpos($folder, $base . DIRECTORY_SEPARATOR) !== 0) throw new Exception('Invalid source path');
            $data = json_decode(file_get_contents($folder.'/event.json'), true);
            if (!isset($data['Event']['Attribute']) || $data['Event']['distribution'] !== 0 || $data['Event']['published'] !== false) throw new Exception('Event sharing policy mismatch');
            if (count($data['Event']['Attribute']) !== $source['count']) throw new Exception('Source count mismatch');
            if (in_array($source['status'], array('unavailable','expired_revoke'), true) && $source['count']) throw new Exception('Unavailable source contains attributes');
            foreach ($data['Event']['Attribute'] as $attribute) {
                if ($attribute['to_ids'] !== false || $attribute['distribution'] !== 0 || !in_array($attribute['type'], array('ip-src','ip-dst'))) throw new Exception('Context attribute policy mismatch');
            }
            $event = $this->Event->find('first', array('conditions'=>array('Event.uuid'=>$data['Event']['uuid']), 'fields'=>array('id','org_id','info','timestamp'), 'recursive'=>-1));
            if ($event && $event['Event']['org_id'] != $user['org_id']) throw new Exception('Existing event belongs to another organisation');
            if ($event && $event['Event']['info'] !== $data['Event']['info']) throw new Exception('Existing event is outside managed source scope');
            $existing = $this->Feed->find('all', array('conditions'=>array('OR'=>array(array('Feed.url'=>$folder), array('Feed.url'=>$source['source_url']))), 'recursive'=>-1));
            if (count($existing)>1) throw new Exception('Duplicate feed definitions require reconciliation before import');
            $old = $event ? $this->MispAttribute->find('count', array('recursive'=>-1,'conditions'=>array_merge($recentConditions,array($a.'.event_id'=>$event['Event']['id'])))) : 0;
            $projected += count($data['Event']['Attribute']) - $old;
            $prepared[] = array($source, $folder, $data, $event, $existing);
        }
        if ($projected >= 100000) throw new Exception('Projected recent IP attribute volume exceeds Manager snapshot bound');
        $warnings = $this->Warninglist->find('count', array('conditions'=>array('enabled'=>true)));
        $summary = array('distribution'=>0,'to_ids'=>false,'external_sharing'=>false,'enabled_warninglists'=>$warnings,'projected_recent_ip_attributes'=>$projected,'sources'=>array());
        if (isset($this->args[1]) && $this->args[1] === 'dry-run') {
            $summary['dry_run']=true;
            $summary['import_ready']=(bool)$warnings;
            $summary['sources']=array_map(function($item) { return array('id'=>$item[0]['id'],'count'=>$item[0]['count'],'status'=>$item[0]['status']); }, $prepared);
            echo json_encode($summary).PHP_EOL; return;
        }
        if (!$warnings) throw new Exception('Enable the intended native MISP warninglists before import');
        foreach ($prepared as $item) {
            list($source, $folder, $data, $priorEvent, $existing) = $item;
            $feedData = array('name'=>$source['name'].' [local managed IP context]', 'provider'=>$source['provider'], 'url'=>$folder, 'input_source'=>'local', 'source_format'=>'misp', 'distribution'=>0, 'enabled'=>$source['status']!=='unavailable', 'caching_enabled'=>false, 'publish'=>false, 'fixed_event'=>false, 'override_ids'=>true, 'delta_merge'=>true, 'settings'=>json_encode(array('local_managed_ip_context'=>true,'source_url'=>$source['source_url'],'source_health'=>$source)));
            if ($existing) { $this->Feed->id=$existing[0]['Feed']['id']; $feedData['id']=$this->Feed->id; }
            else $this->Feed->create();
            if (!$this->Feed->save(array('Feed'=>$feedData))) throw new Exception('Feed configuration save failed');
            $feed = $this->Feed->find('first', array('conditions'=>array('Feed.id'=>$this->Feed->id), 'recursive'=>-1));
            $report = array('id'=>$this->Feed->id,'source_id'=>$source['id'],'source_status'=>$source['status'],'expected_attributes'=>count($data['Event']['Attribute']));
            $data['Event']['Orgc']=array('uuid'=>$org['Organisation']['uuid'],'name'=>$org['Organisation']['name']);
            $eventFile=$folder.'/'.$data['Event']['uuid'].'.json';
            if (file_put_contents($eventFile,json_encode($data)) === false) throw new Exception('Cannot prepare local native event');
            if ($data['Event']['Attribute'] && (!$priorEvent || (int)$priorEvent['Event']['timestamp'] < (int)$data['Event']['timestamp'])) {
                $saved=$this->Feed->downloadAndSaveEventFromFeed($feed,$data['Event']['uuid'],$user);
                if (!is_array($saved) || !isset($saved['result']) || ($saved['result'] !== true && $saved['result'] !== 'No change')) throw new Exception('Native MISP event import failed');
            }
            $event=$this->Event->find('first',array('conditions'=>array('Event.uuid'=>$data['Event']['uuid']),'fields'=>array('id','distribution','org_id','published'),'recursive'=>-1));
            if ($event) {
                if ($event['Event']['distribution'] != 0 || $event['Event']['org_id'] != $user['org_id'] || $event['Event']['published']) throw new Exception('Imported event scope mismatch');
                $incoming=array_column($data['Event']['Attribute'],'uuid');
                $conditions=array($a.'.event_id'=>$event['Event']['id'],$a.'.deleted'=>false);
                if ($incoming) $conditions['NOT']=array($a.'.uuid'=>$incoming);
                $removed=$this->MispAttribute->find('list',array('recursive'=>-1,'conditions'=>$conditions,'fields'=>array('id','id')));
                foreach ($removed as $id) { $this->MispAttribute->id=$id; if (!$this->MispAttribute->save(array('id'=>$id,'deleted'=>true,'to_ids'=>false),array('validate'=>false,'fieldList'=>array('deleted','to_ids')))) throw new Exception('Source-scoped revocation failed'); }
                $conditions=array($a.'.event_id'=>$event['Event']['id'],$a.'.deleted'=>false);
                $report['active_attributes']=$this->MispAttribute->find('count',array('recursive'=>-1,'conditions'=>$conditions));
                $report['actionable_attributes']=$this->MispAttribute->find('count',array('recursive'=>-1,'conditions'=>array_merge($conditions,array($a.'.to_ids'=>true))));
                $report['revoked']=count($removed); $report['event_id']=$event['Event']['id'];
                if ($report['active_attributes'] != $report['expected_attributes'] || $report['actionable_attributes']) throw new Exception('Imported context verification failed');
                $expected=array();
                foreach ($data['Event']['Attribute'] as $attribute) $expected[$attribute['uuid']]=$attribute;
                $actual=$this->MispAttribute->find('all',array('recursive'=>-1,'conditions'=>$conditions,'fields'=>array('uuid','value','type','timestamp','to_ids','distribution')));
                foreach ($actual as $row) {
                    $attribute=$row[$a];
                    if (!isset($expected[$attribute['uuid']])) throw new Exception('Unexpected managed attribute identity');
                    $wanted=$expected[$attribute['uuid']];
                    if ($attribute['value'] !== $wanted['value'] || $attribute['type'] !== $wanted['type'] || (int)$attribute['timestamp'] !== (int)$wanted['timestamp'] || $attribute['to_ids'] || !in_array((int)$attribute['distribution'],array(0,5),true)) throw new Exception('Managed attribute value, freshness or policy mismatch');
                }
            } else {
                if ($report['expected_attributes']) throw new Exception('Imported event missing');
                $report['active_attributes']=0; $report['actionable_attributes']=0;
            }
            $summary['sources'][]=$report;
        }
        echo json_encode($summary).PHP_EOL;
    }
}
