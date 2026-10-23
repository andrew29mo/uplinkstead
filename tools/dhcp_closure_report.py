"""Fail-closed qualification of installed-service closure and resource observations."""
import copy,html,json,math,statistics
from .dhcp_stage1_report import require
from .evidence import fingerprint

def resource_summary(rows):
    require(len(rows)>=230,'Too few samples')
    times=[r['at'] for r in rows];require(all(type(t) in (int,float) and math.isfinite(t) for t in times) and all(b>a for a,b in zip(times,times[1:])) and times[-1]-times[0]>=500,'Insufficient bounded duration')
    stable=[r for r in rows if r['phase']=='baseline' or r['phase']=='tail' or r['phase'].endswith(('-steady','-recovered'))]
    require(len(stable)>=200,'Too few comparable stable samples')
    n=max(1,len(stable)//3);out={}
    for role in ('writer','worker','clientA','clientB'):
        require(len({(r['processes'][role]['pid'],r['processes'][role]['start_ticks']) for r in rows})==1,'Hidden service restart in resource series')
        for metric,allowance in (('rss_kib',4096 if role=='writer' else 1024 if role=='worker' else 512),('fd',2),('threads',2)):
            values=[r['processes'][role][metric] for r in stable]
            require(all(type(x) is int and x>0 for x in values),'Invalid resource sample')
            first=statistics.median(values[:n]);last=statistics.median(values[-n:]);delta=last-first
            t=[r['at']-stable[0]['at'] for r in stable];mean=statistics.mean(t);avg=statistics.mean(values)
            slope=sum((x-mean)*(y-avg) for x,y in zip(t,values))/sum((x-mean)**2 for x in t)
            out[role+'_'+metric]=dict(first_third_median=first,last_third_median=last,delta=delta,min=min(values),max=max(values),slope_per_minute=slope*60,delta_allowance=allowance)
            peak_limit=first+allowance if metric=='rss_kib' else (24 if role=='writer' else 8) if metric=='fd' else (13 if role=='writer' else 2)
            out[role+'_'+metric]['peak_limit']=peak_limit
            require(delta<=allowance and max(values)<=peak_limit,'Resource growth budget exceeded')
    tail=[r for r in rows if r['phase']=='tail'];require(len(tail)>=100 and tail[-1]['at']-tail[0]['at']>=250,'Missing extended steady tail')
    n=len(tail)//3;out['tail']={}
    for role in ('writer','worker','clientA','clientB'):
        for metric in ('rss_kib','fd','threads'):
            values=[r['processes'][role][metric] for r in tail];delta=statistics.median(values[-n:])-statistics.median(values[:n]);limit=(256 if role=='writer' else 64) if metric=='rss_kib' else 0
            out['tail'][role+'_'+metric]=dict(first_third_median=statistics.median(values[:n]),last_third_median=statistics.median(values[-n:]),delta=delta,delta_allowance=limit)
            require(delta<=limit,'Extended-tail growth budget exceeded')
    require(all(r['db_bytes']<=8388608 and r['disk_bytes']<=16777216 and r['queue']['depth']<=r['queue']['capacity']==8 and r['queue']['peak']<=8 and r['recent_count']<=16 and r['selection_count']<=16 and not r['errors'] for r in rows),'Storage/queue/error resource bound exceeded')
    out.update(samples=len(rows),stable_samples=len(stable),seconds=times[-1]-times[0],disk_first=rows[0]['disk_bytes'],disk_last=rows[-1]['disk_bytes'],disk_max=max(r['disk_bytes'] for r in rows),cgroup_processes_min=min(r['cgroup_processes'] for r in rows),cgroup_processes_max=max(r['cgroup_processes'] for r in rows))
    require(out['cgroup_processes_min']>=4 and out['cgroup_processes_max']<=12,'Unexpected service process count')
    return out

def verify(v):
    require(v['passed'] is True and v['source_sha256']==fingerprint(v['source']) and v['source_changed'] is False,'Failed/changed source')
    require(v['fresh_profile'] is True and v['data_disk_initially_absent'] is True and v['data_disk_removed'] is True and v['vm_final']=='Deleted' and v['host_mounts']=='none','Not a fresh isolated/cleaned VM')
    require(v['stages'] and all(r['exit_code']==0 and r['timed_out'] is False and math.isfinite(r['seconds']) and r['seconds']>=0 for r in v['stages']),'Failed/timed out stage')
    for key,name in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==name and r['source_sha256']==v['source_sha256'] and r['failures']==r['errors']==r['skipped']==0 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['count']>=284,'Different/failed portable suite')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different platform tests')
    g=v['guest'];i=g['installation'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'] and g['initial_package']=='absent' and g['initial_account_absent'] is True,'Not clean/formal guest')
    require(i['wheel_sha256']==v['wheel_sha256'] and i['documentation_sha256']==v['documentation_sha256'] and i['recipe_sha256']==v['recipe_sha256'],'Package/documentation mismatch')
    modules={k:h for k,h in v['source'].items() if k.startswith('uplinkstead/') and k.endswith('.py')}
    require(i['package']['files']==modules and i['source_package_absent'] is True and i['package']['location'].startswith('/usr/local/lib/python3.12/') and 'PYTHONPATH' not in g['service_environment'],'Installed modules/provenance mismatch')
    for u in ('uplinkstead-dual.service','uplinkstead-dual-policy.service'):
        require(i['units'][u]['source']==i['units'][u]['installed']==v['source']['deploy/'+u] and i['namespace_only_dropins'][u]=='[Service]\nNetworkNamespacePath=/run/netns/dd_r\n','Different formal service')
    require(i['hook_installed']==v['source']['deploy/uplinkstead-dual-hook.py'] and i['worker_installed']==v['source']['uplinkstead/dual_dhcp_worker.py'] and i['client_installed']==i['client']['binary_sha256'],'Different client/hook/worker')
    require(g['worker']['uid'][0]>0 and len(set(g['worker']['uid']))==1 and all(int(x,16)==0 for x in g['worker']['caps'].values()) and g['worker']['no_new_privs']=='1' and g['writer']['uid']==[0]*4 and g['service']['Type']=='notify','Privilege/readiness mismatch')
    require(g['sample_errors']==[] and g['scope_before']==g['scope_after'],'Sampler failure/scope change')
    require(len(g['cycles'])==6,'Missing complete fault cycles')
    history=g['baseline']['state']['history']
    for c in g['cycles']:
        a,b,e=(c[k]['state'] for k in ('before','after','settled'));other='B' if c['fault_link']=='A' else 'A'
        require(a['history']==history and a['active']['link']==c['fault_link'] and b['active']['link']==e['active']['link']==other and b['history'][:-1]==history and len(b['history'])==len(history)+1 and e['history']==b['history'] and not e['latched'] and c['client']['ok'] is True and c['client']['response']['peer']==('10.99.1.1' if other=='A' else '10.99.2.1'),'Cycle/fresh data/budget mismatch')
        for k,r in e['links'].items():require(r['current'] is not None and r['state']=='HEALTHY' and r['until']>c['settled']['runtime']['as_of'] and r['expires']>c['settled']['runtime']['as_of'],'No fresh lease/health after fault')
        history=b['history']
    require(g['soak_final']['state']['history']==history,'Natural renewal consumed budget')
    for k in ('A','B'):
        require(g['soak_final']['state']['links'][k]['event_sequence']-g['baseline']['state']['links'][k]['event_sequence']>=10 and g['wire_counters'][k]['wrong_dhcp']==0,'Insufficient renewals/borrowed DHCP')
    require(v['resources']==resource_summary(g['samples']),'Resource summary mismatch')
    ops=g['operations'];require([o['operation'] for o in ops]==['status','pause','reset-budget','resume','resume','pause'] and all((o['exit_code']==0)==o['answer']['ok'] for o in ops) and [o['answer']['ok'] for o in ops]==[True,True,True,False,True,False],'Operator/stale operation mismatch')
    h=g['handoff'];require(h['paused']['state']['paused'] is True and h['reset']['state']['paused'] is True and h['reset']['state']['history']==[] and h['stopped']['active'] is None and all(r['current'] is None for r in h['stopped']['links'].values()) and h['old_processes_gone'] is True and h['cgroups_empty'] is True and h['blocked']['ok'] is False and h['fallback']['ok'] is True and h['new']['state']['epoch']>h['old']['state']['epoch'] and all(h['new']['state']['links'][k]['session']!=h['old']['state']['links'][k]['session'] for k in ('A','B')),'Stop/restart/handoff failed')
    require(all(g['cleanup'][k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped','services_stopped')),'Cleanup failed')
    require(v['power_loss_tested'] is False and v['boot_zero_gap_tested'] is False,'Untested claim')
    return True

def controls(v):
    changes=[lambda x:x.update(data_disk_removed=False),lambda x:x.update(data_disk_initially_absent=False),lambda x:x.update(source_changed=True),lambda x:x['stages'][0].update(exit_code=1),lambda x:x['stages'][0].update(timed_out=True),lambda x:x.update(fresh_profile=False),lambda x:x.update(vm_final='Running'),lambda x:x['guest']['installation'].update(source_package_absent=False),lambda x:x['guest']['installation']['package']['files'].clear(),lambda x:x['guest']['cycles'].pop(),lambda x:x['guest']['cycles'][0]['settled']['state']['history'].clear(),lambda x:x['guest']['operations'][-1]['answer'].update(ok=True),lambda x:x['guest']['samples'][-1]['processes']['writer'].update(start_ticks='changed'),lambda x:x['guest']['samples'][-1].update(db_bytes=999999999),lambda x:x['guest']['cleanup'].update(services_stopped=False),lambda x:x.update(power_loss_tested=True)]
    for change in changes:
        b=copy.deepcopy(v);change(b)
        try:verify(b)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupt closure evidence accepted')
    return dict(passed=True,rejected=len(changes))

def render(v):
    return '<!doctype html><html lang="en"><meta charset="utf-8"><title>Uplinkstead DHCP MVP closure</title><style>body{font:16px system-ui;max-width:1100px;margin:40px auto;padding:0 20px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style><h1>Clean install and bounded renewal/fault soak</h1><p>Passed: '+str(v.get('passed',False))+'</p><p>Installed wheel and shipped systemd services; namespace-only isolation. Short controlled Linux VM observations, not physical-WAN or long-term leak qualification. Resource bounds are explicit, not a zero-growth guarantee. No power loss, reboot or boot-zero-gap tested in this run; prior reboot evidence is separate.</p><h2>Resource summary</h2><pre>'+html.escape(json.dumps(v.get('resources',{}),indent=2))+'</pre><h2>Complete JSON evidence</h2><pre>'+html.escape(json.dumps(v,indent=2,allow_nan=False))+'</pre></html>'
