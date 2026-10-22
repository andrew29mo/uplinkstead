"""Fail-closed absolute timer evidence checks, also effective under python -O."""
import copy,math,re
from tools.evidence import fingerprint
from tools.dhcp_stage1_report import require,render as base_render,identity
from tools.dhcp_p0_report import packet,stable
from tools.dhcp_client_build import TARBALL_SHA256,UPSTREAM_DHCPC_SHA256,PATCHED_DHCPC_SHA256
from uplinkstead.dhcp_timing import timer_values

CASES={'default_T1_and_independent_A','explicit_T1_two_natural_rounds','partial_option_default_T2','invalid_options_do_not_extend_or_replace','natural_T2_rebind_and_delayed_real_ACK','no_early_loss_expiry_withdrawal_and_reacquisition'}

def transaction(t):
    req,ack,r,d,s=(t[k] for k in ('request','ack','runtime_record','timer','status'));row=s['state']['links'][r['link']]
    packet(req,3);packet(ack,5,req['chaddr'])
    require(req['xid']==ack['xid']==r['xid']==d['xid'] and req['at']<=ack['at'],'Wire/client transaction mismatch')
    a,b=timer_values(int(ack['lease']),ack['renewal'],ack['rebinding'])
    require(d['event']=='ack' and d['origin']==r['client_origin_ns'] and d['t1']==d['origin']+a and d['t2']==d['origin']+b and d['expiry']==d['origin']+int(ack['lease'])*10**9,'Client timer detached from options')
    require(r['request_at']==min(r['wire_request_at'],r['client_origin_ns']/1e9) and row['expires']==r['expires']==r['request_at']+int(ack['lease']) and r in s['runtime']['recent'],'Lease origin/deadline mismatch')
    require(r['sequence']==row['event_sequence'] and ack['ip']==row['current']['ip'] and r['request_at']<=req['at'] and r['processed_at']<=s['runtime']['as_of'],'Runtime allocation mismatch')
    require(d['origin']<=d['at']<d['expiry'] and d['pid']==s['runtime']['children'][r['link']],'Wrong client process')

def natural(before,after):
    transaction(before);transaction(after)
    require(before['ack']['xid']!=after['ack']['xid'] and after['request']['at']>=before['timer']['t1']/1e9 and after['request']['destination']==before['ack']['router'],'Not a natural unicast T1 request')
    for k in ('A','B'):stable(k,before['status'],after['status'])

def fence(e):
    before,mid,after,p=(e[k] for k in ('before','capture_fence','after','received'));packet(p,5)
    b,c,a=(s['runtime']['capture']['B'] for s in (before,mid,after))
    require(before['runtime']['as_of']<=p['at']<=c['empty_at'] and mid['runtime']['as_of']<after['runtime']['as_of'] and any(x['frame_sha256']==p['frame_sha256'] and x['frame_index']>b['frames'] for x in c['seen_frames']),'No production capture/processing fence')
    require(identity(before['state']['links']['B'])==identity(after['state']['links']['B']) and before['state']['links']['B']['event_sequence']==after['state']['links']['B']['event_sequence'] and a['version']==b['version'] and a['pending'] is False,'Rejected ACK changed production allocation')

def verify(v):
    require(v['passed'] is True and v['source_changed'] is False and v['source_sha256']==fingerprint(v['source']),'Failed/source changed')
    expected={'native','initial','start','preflight','upload','build','linux','linux-read','cases','cleanup','remove','stop','final'}
    require(len(v['stages'])==len(expected) and {s['name'] for s in v['stages']}==expected,'Missing stage')
    for s in v['stages']:require(s['exit_code']==0 and s['timed_out'] is False and math.isfinite(s['seconds']) and s['seconds']>=0,'Stage failed/timeout')
    for key,platform in (('native_unit','Darwin'),('linux_unit','Linux')):
        r=v[key];require(r['passed'] is True and r['platform']==platform and r['source_sha256']==v['source_sha256'] and r['count']>=211 and r['count']==len(r['tests'])==len(set(r['tests'])) and r['errors']==r['failures']==r['skipped']==0,'Portable tests failed')
    require(v['native_unit']['tests']==v['linux_unit']['tests'],'Different tests')
    g=v['guest'];require(g['passed'] is True and g['source_sha256']==v['source_sha256'],'Guest failed/source')
    require(len(g['cases'])==len(CASES) and {c['name'] for c in g['cases']}==CASES,'Missing scenario')
    for c in g['cases']:require(c['passed'] is True and math.isfinite(c['seconds']) and c['seconds']>=0,'Scenario failed')
    for c in (g['cleanup'],v['cleanup']):require(all(c[k] is True for k in ('namespaces_removed','root_network_unchanged','owned_children_reaped')),'Cleanup failed')
    require(v['snapshot_removed'] is True and v['vm_final']=='Stopped','VM not cleaned')
    b=g['client_build'];require(b['source_tar_sha256']==TARBALL_SHA256 and b['upstream_dhcpc_sha256']==UPSTREAM_DHCPC_SHA256 and b['patched_dhcpc_sha256']==PATCHED_DHCPC_SHA256 and b['recipe_sha256']==v['source']['tools/dhcp_client_build.py'] and g['client_binary_sha256']==b['binary_sha256'],'Client provenance mismatch')
    d={c['name']:c['details'] for c in g['cases']}
    c=d['default_T1_and_independent_A'];natural(c['baseline'],c['renewed']);natural(c['A_baseline'],c['A_renewed'])
    require(c['baseline']['ack']['timer58'] is None and c['baseline']['ack']['timer59'] is None and c['client']['ok'] is True,'Defaults not exercised')
    require(c['rss_kib']['service']>0 and all(c['rss_kib']['clients'][k]>0 for k in ('A','B')),'RSS missing')
    c=d['explicit_T1_two_natural_rounds'];require(len(c['rounds'])==2,'Missing repeated renewal');previous=c['baseline']
    for t in c['rounds']:natural(previous,t);previous=t
    require(previous['ack']['renewal']==10 and previous['ack']['rebinding']==25,'Wrong explicit options')
    c=d['partial_option_default_T2'];natural(c['baseline'],c['renewed']);require(c['baseline']['ack']['renewal']==8 and c['baseline']['ack']['timer59'] is None,'Partial options not exercised')
    c=d['invalid_options_do_not_extend_or_replace'];require(len(c['attempts'])==4,'Missing malformed/reversed timer cases')
    expected=[{'58':0,'59':25},{'58':30,'59':25},{'58':10,'59':120},{'58':{'hex':'000001'},'59':25}]
    for e,options in zip(c['attempts'],expected):
        fence(e);require(bool(e['received']['timer_error']) and e['options']==options,'Invalid timer cases missing/substituted')
        for code,value in options.items():
            encoded=value['hex'] if isinstance(value,dict) else value.to_bytes(4,'big').hex()
            require(e['received']['timer'+code]==encoded,'Invalid options detached from wire')
        rejected=e['client_rejection'];before=e['before'];old=before['state']['links']['B']
        record=next(r for r in reversed(before['runtime']['recent']) if r['link']=='B' and r['sequence']==old['event_sequence'])
        require(rejected['event']=='reject' and rejected['interface']=='wanB' and rejected['xid']==e['received']['xid'] and rejected['pid']==before['runtime']['children']['B'] and rejected['origin']==record['client_origin_ns'] and rejected['expiry']==rejected['origin']+old['current']['seconds']*10**9 and rejected['at']/1e9>=before['runtime']['as_of'],'Client rejection detached from live schedule')
    c=d['natural_T2_rebind_and_delayed_real_ACK'];transaction(c['baseline']);transaction(c['rebound']);fence(c['rejected'])
    require(c['broadcast']['destination']=='255.255.255.255' and c['broadcast']['at']>=c['baseline']['timer']['t2']/1e9 and c['unicast']['at']>=c['baseline']['timer']['t1']/1e9 and c['unicast']['destination']=='198.51.100.1','No natural T1/T2')
    require(c['broadcast']['xid']==c['rebound']['ack']['xid']!=c['unicast']['xid'] and c['rejected']['received']['xid']==c['unicast']['xid'] and c['rejected']['received']['at']>=c['broadcast']['at'] and c['held_origin']['delayed'] is True and c['held_origin']['frame_sha256']==c['rejected']['received']['frame_sha256'] and c['held_origin']['request_at']<c['broadcast']['at'] and c['client']['ok'] is True,'Delayed actual ACK not proved')
    c=d['no_early_loss_expiry_withdrawal_and_reacquisition'];transaction(c['baseline']);transaction(c['reacquired']);fence(c['replay'])
    diag=c['third_retry'];deadline=c['baseline']['timer']['expiry'];row=c['checkpoint']['state']['links']['B']
    broadcasts=[p for p in c['expiry_requests'] if p['destination']=='255.255.255.255' and p['ciaddr']!='0.0.0.0' and p['at']<=c['checkpoint']['runtime']['as_of']]
    require(len(broadcasts)>=3 and len({p['xid'] for p in broadcasts})==1 and broadcasts[0]['at']>=c['baseline']['timer']['t2']/1e9,'Three real broadcast attempts missing')
    require(diag['event']=='rebind' and diag['attempts']>=3 and diag['at']<deadline and c['checkpoint']['runtime']['as_of']<deadline/1e9 and row['current'] and c['live']['ok'] is True,'No proof of retaining lease after three attempts')
    require(c['expiration']['event']=='expire' and c['expiration']['at']>=deadline and c['expiration']['expiry']==deadline and c['expired']['state']['links']['B']['current'] is None and c['expired']['state']['active'] is None and c['blocked']['ok'] is False,'True expiry withdrawal missing')
    require(not any(a.get('local')=='198.51.100.2' for link in c['network']['addresses'] for a in link.get('addr_info',[])) and not any(str(r.get('table')) in ('41202','41203') for r in c['network']['routes']),'Expired address/route retained')
    require(c['reacquired']['ack']['ip']=='198.51.100.3' and c['client_A']['ok'] is True and c['client_B']['ok'] is True,'Reacquisition/isolation failed')
    require(all(g['wire_counters'][k]['wrong_dhcp']==0 for k in ('A','B')),'Borrowed DHCP path')
    return True

def controls(v):
    def alter(name,fn):return lambda x:fn(next(c['details'] for c in x['guest']['cases'] if c['name']==name))
    changes=[lambda x:x.update(passed=False),lambda x:x.update(source_changed=True),lambda x:x['stages'][0].update(timed_out=True),lambda x:x['stages'][0].update(exit_code=1),lambda x:x['stages'].pop(),lambda x:x['native_unit'].update(skipped=1),lambda x:x['linux_unit'].update(source_sha256='0'*64),lambda x:x['guest']['cases'].pop(),lambda x:x['cleanup'].update(root_network_unchanged=False),lambda x:x.update(vm_final='Running'),lambda x:x.update(snapshot_removed=False),lambda x:x['guest']['client_build'].update(binary_sha256='0'*64)]
    changes += [alter('default_T1_and_independent_A',lambda d:d['baseline']['timer'].update(t1=0)),alter('explicit_T1_two_natural_rounds',lambda d:d['rounds'].pop()),alter('partial_option_default_T2',lambda d:d['baseline']['ack'].update(timer59='00000064')),alter('invalid_options_do_not_extend_or_replace',lambda d:d['attempts'][0]['capture_fence']['runtime']['capture']['B'].update(seen_frames=[])),alter('invalid_options_do_not_extend_or_replace',lambda d:d['attempts'][0]['after']['state']['links']['B'].update(expires=0)),alter('natural_T2_rebind_and_delayed_real_ACK',lambda d:d['broadcast'].update(at=0)),alter('natural_T2_rebind_and_delayed_real_ACK',lambda d:d['held_origin'].update(delayed=False)),alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['third_retry'].update(attempts=2)),alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['expiration'].update(at=0)),alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['blocked'].update(ok=True)),alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['reacquired']['ack'].update(ip='198.51.100.2')),lambda x:x['guest']['wire_counters']['B'].update(wrong_dhcp=1)]
    changes += [alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['network']['routes'].append(dict(table='41203',dst='default',gateway='198.51.100.1'))),
        alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['network']['routes'].append(dict(table=41202,dst='198.51.100.0/24'))),
        alter('no_early_loss_expiry_withdrawal_and_reacquisition',lambda d:d['network']['addresses'][0].setdefault('addr_info',[]).append(dict(local='198.51.100.2'))),
        alter('invalid_options_do_not_extend_or_replace',lambda d:d['attempts'][0]['client_rejection'].update(event='ack')),
        alter('invalid_options_do_not_extend_or_replace',lambda d:d['attempts'][1].update(options=d['attempts'][0]['options']))]
    for change in changes:
        broken=copy.deepcopy(v);change(broken)
        try:verify(broken)
        except (ValueError,KeyError,TypeError):pass
        else:raise ValueError('Corrupt timer evidence accepted')
    return dict(passed=True,rejected=len(changes))

def render(v):
    return base_render(v).replace('Uplinkstead DHCP stage 1','Uplinkstead DHCP absolute timers').replace('Formal dual-DHCP stage-one service','Formal client T1/T2 and expiry evidence').replace('Lease origin is a conservative REQUEST receive-queue-empty lower bound, not hook or processing time.','Lease origin is the earlier of the formal client REQUEST origin and capture-queue lower bound. B uses a deterministic fault server; A uses dnsmasq. RSS is a VM snapshot, not a peak. No full RFC interoperability claim.')
