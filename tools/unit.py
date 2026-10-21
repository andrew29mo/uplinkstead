import argparse
import io
import json
import platform
from pathlib import Path
import unittest
from .evidence import manifest,fingerprint


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',required=True);a=p.parse_args()
    suite=unittest.defaultTestLoader.discover('tests')
    def ids(t):
        if isinstance(t,unittest.TestSuite):return [i for s in t for i in ids(s)]
        return [t.id()]
    names=ids(suite);stream=io.StringIO();r=unittest.TextTestRunner(stream=stream,verbosity=2).run(suite)
    source=manifest()
    receipt=dict(passed=r.wasSuccessful() and not r.skipped,tests=names,count=r.testsRun,
                 failures=len(r.failures),errors=len(r.errors),skipped=len(r.skipped),
                 source_sha256=fingerprint(source),platform=platform.system(),python=platform.python_version())
    Path(a.output).write_text(json.dumps(receipt,indent=2)+'\n')
    print(stream.getvalue());raise SystemExit(0 if receipt['passed'] else 1)
if __name__=='__main__':main()
