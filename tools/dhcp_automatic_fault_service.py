"""VM-only barrier around production Backend.select; never installed as a service.

Delegates every kernel operation to the real backend. The only injection is a
bounded pause after actual select readback, before the production writer returns.
No mocked health, lease admission, selection result or recovery implementation.
"""
import json
from pathlib import Path
import sys,time
from uplinkstead import dual_dhcp_service as service
from uplinkstead.dual_dhcp_linux import Backend
from uplinkstead.writer import now

root=Path(sys.argv[sys.argv.index('--config')+1]).parent
class BarrierBackend(Backend):
    def select(self,allowed,active,deadline):
        super().select(allowed,active,deadline)
        arm=root/'barrier-arm.json'
        if active and arm.exists():
            request=json.loads(arm.read_text())
            if request['link']==active['link']:
                arm.unlink();began=now()
                (root/'barrier-ready.json').write_text(json.dumps(dict(at=began,active=active,deadline=deadline)))
                while not (root/'barrier-release').exists():
                    if now()-began>3:raise TimeoutError('Test barrier release absent')
                    time.sleep(.005)
                (root/'barrier-done.json').write_text(json.dumps(dict(at=now())))
service.Backend=BarrierBackend
if __name__=='__main__':service.main()
