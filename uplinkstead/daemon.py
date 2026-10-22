"""Privileged writer service; configuration and executable are deployment-owned."""
import argparse
from pathlib import Path
import pwd
import signal
import threading
from .config import load
from .control import serve
from .writer import Writer


def main():
    p=argparse.ArgumentParser();p.add_argument('--config',type=Path,required=True);p.add_argument('--state',type=Path,required=True)
    p.add_argument('--socket',type=Path,required=True);p.add_argument('--agent-user',default='uplinkstead');a=p.parse_args()
    stopped=threading.Event()
    for sig in (signal.SIGTERM,signal.SIGINT):signal.signal(sig,lambda *_:stopped.set())
    with Writer(load(a.config),a.state,initial_mode='DISABLED') as writer:
        serve(writer,a.socket,pwd.getpwnam(a.agent_user).pw_uid,stopped)


if __name__=='__main__':main()
