"""Rebuild only the locked project; downloaded publication assets stay intact."""
import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

from verify_release101 import LOCK_SHA, PINS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-root', type=Path, required=True)
    parser.add_argument('--project-lock', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert hashlib.sha256(args.project_lock.read_bytes()).hexdigest() == LOCK_SHA
    assert importlib.metadata.version('hatchling') == '1.33.0'
    assert importlib.metadata.version('twine') == '7.0.0'
    lock = json.loads(args.project_lock.read_bytes())
    args.out.mkdir(parents=True, exist_ok=False)
    project = args.out / 'project'
    for name, expected in lock['project_files'].items():
        source = args.source_root / name
        assert hashlib.sha256(source.read_bytes()).hexdigest() == expected, name
        target = project / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    env = {key: os.environ[key] for key in ('PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL') if key in os.environ}
    env.update(SOURCE_DATE_EPOCH='1794873600', PYTHONHASHSEED='0', PYTHONDONTWRITEBYTECODE='1')
    here = Path(__file__).resolve().parent
    result = subprocess.run([sys.executable, str(here / 'offline_hatch.py'), 'build', '-t', 'wheel', '-t', 'sdist'],
                            cwd=project, env=env, capture_output=True, text=True)
    (args.out / 'build.stdout.txt').write_text(result.stdout)
    (args.out / 'build.stderr.txt').write_text(result.stderr)
    assert result.returncode == 0, result.stderr
    assert {p.name for p in (project / 'dist').iterdir()} == set(PINS)
    assert all(hashlib.sha256((project / 'dist' / n).read_bytes()).hexdigest() == h for n, h in PINS.items())
    subprocess.run([sys.executable, str(here / 'verify_release101.py'), '--dist', str(project / 'dist'),
                    '--project-lock', str(args.project_lock.resolve()), '--source-root', str(project),
                    '--out', str(args.out / 'REBUILD_ARCHIVE_PROOF.json')], check=True)
    print(json.dumps({'status': 'FROZEN_SOURCE_REBUILD_IDENTICAL', 'source_files': len(lock['project_files']),
                      'SOURCE_DATE_EPOCH': env['SOURCE_DATE_EPOCH'], 'hatchling': '1.33.0', 'twine': '7.0.0',
                      'artifacts': PINS, 'publication_assets_replaced': False, 'model_calls': 0}))


if __name__ == '__main__':
    main()
