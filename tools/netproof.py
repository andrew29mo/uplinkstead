"""Structural network snapshots: preserve rule order and operands, omit only counters/IDs."""
import copy
import hashlib
import json
import re


def nft_semantics(value):
    if isinstance(value,list):return [nft_semantics(x) for x in value]
    if not isinstance(value,dict):return value
    result={}
    for key,item in value.items():
        if key=='handle':continue
        if key=='counter' and isinstance(item,dict):
            item={k:v for k,v in item.items() if k not in ('packets','bytes')}
        result[key]=nft_semantics(item)
    return result


def xt_semantics(text):
    return '\n'.join(re.sub(r'^(:[^ ]+ [^ ]+) \[\d+:\d+\]$',r'\1 [counters]',line)
                     for line in text.splitlines() if line and not line.startswith('#'))


def semantics(raw):
    return dict(rules=raw['rules'],routes=raw['routes'],nft=nft_semantics(json.loads(raw['nft'])),
                iptables=xt_semantics(raw['iptables']),ip6tables=xt_semantics(raw['ip6tables']))


def digest(raw):
    return hashlib.sha256(json.dumps(semantics(raw),sort_keys=True,separators=(',',':')).encode()).hexdigest()
