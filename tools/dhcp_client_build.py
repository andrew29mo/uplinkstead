"""Build an experimental GPL-2.0 BusyBox adapter from verified external source.

No third-party source or binary is bundled. The transformation is deliberately
small: never reuse xid in one client process, start a new transaction at BOUND.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile

TARBALL_SHA256='b8cc24c9574d809e7279c3be349795c5d5ceb6fdf19ca709f80cde50e47de314'
URL='https://busybox.net/downloads/busybox-1.36.1.tar.bz2'
UPSTREAM_DHCPC_SHA256='4c2f9169dd2ecc4083e0dd31e79437c43fb5bbe24db42c5322e94fc3d8e0b5cc'
PATCHED_DHCPC_SHA256='6af6206761c6b0037be3645b5a84b3cce782d4109293395279cbf722bb5862b6'
OLD='''static ALWAYS_INLINE uint32_t random_xid(void)
{
\treturn rand();
}'''
NEW='''static ALWAYS_INLINE uint32_t random_xid(void)
{
\tstatic uint32_t next;
\tstatic uint64_t issued;
\tif (issued == 0)
\t\tnext = rand();
\tif (issued >= 0x100000000ULL)
\t\tbb_simple_error_msg_and_die("xid sequence exhausted");
\tissued++;
\treturn next++;
}'''
RENEW='\t\t\t\t/* client_data.xid = random_xid(); ...but why bother? */'
LOST='\t\t\t\tbb_simple_info_msg("lease lost, entering init state");'
LOSS_DIAGNOSTIC='\t\t\t\tbb_info_msg("uplinkstead_loss if=%s pid=%u xid=%u remaining=%d attempts=%u", client_data.interface, (unsigned)getpid(), (unsigned)ntohl(client_data.xid), lease_remaining, packet_num); fflush(NULL);'


def transform(source):
    if source.count(OLD)!=1 or source.count(RENEW)!=1 or source.count(LOST)!=1:
        raise ValueError('Unsupported upstream source; refusing approximate patch')
    return source.replace(OLD,NEW).replace(RENEW,'\t\t\t\tclient_data.xid = random_xid(); /* Uplinkstead transaction boundary */').replace(LOST,LOSS_DIAGNOSTIC+'\n'+LOST)


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def build(archive, directory):
    if digest(archive)!=TARBALL_SHA256:raise ValueError('Upstream source hash mismatch')
    directory=Path(directory);directory.mkdir(mode=0o700)
    with tarfile.open(archive) as tar:tar.extractall(directory,filter='data')
    source=directory/'busybox-1.36.1';p=source/'networking/udhcp/dhcpc.c';before=digest(p)
    if before!=UPSTREAM_DHCPC_SHA256:raise ValueError('Unexpected client source')
    p.write_text(transform(p.read_text()))
    if digest(p)!=PATCHED_DHCPC_SHA256:raise ValueError('Unexpected transformed client')
    def run(args,**kw):subprocess.run(args,cwd=source,check=True,timeout=180,**kw)
    run(['make','allnoconfig'])
    config=source/'.config';text=config.read_text()
    for key in ('PLATFORM_LINUX','UDHCPC','LONG_OPTS'):
        text=text.replace('# CONFIG_'+key+' is not set','CONFIG_'+key+'=y')
    config.write_text(text);run(['make','oldconfig'],input=b'\n'*1000)
    run(['make','-j2'])
    receipt=dict(upstream_url=URL,source_tar_sha256=TARBALL_SHA256,upstream_dhcpc_sha256=before,
                 patched_dhcpc_sha256=digest(p),config_sha256=digest(config),binary_sha256=digest(source/'busybox'),
                 license='GPL-2.0; upstream source, full transformation and build recipe required for binary redistribution',
                 boundary='process-local nonrepeating xid; new transaction after ACK or scheduled renewal retry; no cross-process cryptographic identity')
    receipt['compiler']=subprocess.check_output(['gcc','--version'],text=True).splitlines()[0]
    receipt['recipe_sha256']=digest(__file__)
    (directory/'build.json').write_text(json.dumps(receipt,indent=2)+'\n')
    return receipt


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--archive',type=Path,required=True);p.add_argument('--directory',type=Path,required=True)
    a=p.parse_args();print(json.dumps(build(a.archive,a.directory)))
