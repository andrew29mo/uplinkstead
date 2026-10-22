import hashlib
import json
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]

def manifest():
    files=[p for d in ('uplinkstead','tools','tests','deploy') for p in (ROOT/d).rglob('*')
           if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.service','.json','.conf')]
    files += [ROOT/'pyproject.toml', ROOT/'LICENSE']
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(files)}

def fingerprint(m):return hashlib.sha256(json.dumps(m,sort_keys=True,separators=(',',':')).encode()).hexdigest()
