"""Read-only verification of the frozen 1.1.0 distribution archives.

This checks artifacts, not publication authorization or model performance.
It never imports the SDK, extracts archive code or contacts a service.
"""
import argparse
import base64
import csv
import hashlib
import io
import json
import re
import tarfile
import zipfile
from email.parser import BytesParser
from pathlib import Path, PurePosixPath

PINS = {
    'spillway_guard-1.1.0-py3-none-any.whl': 'a047c87853638b7faee3c4b32a36d2d8456f5db098fbdaf93416e6bb545a4209',
    'spillway_guard-1.1.0.tar.gz': '0660f75d6a8793dc86c05677c42b22cae4d9a563b7ec512f9ad46cde821946f1',
}
LOCK_SHA = '065cc50d714de85d7a2437b2b0af99d05627b5189d49728cde52bc8eebdf1073'


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--dist', type=Path, required=True)
    parser.add_argument('--project-lock', type=Path, required=True)
    parser.add_argument('--source-root', type=Path)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    assert not args.out.exists(), 'Preserve existing artifact review receipts'
    assert sha(args.project_lock.read_bytes()) == LOCK_SHA
    lock = json.loads(args.project_lock.read_bytes())
    assert lock['version'] == '1.1.0' and lock['package_count'] == 35
    assert {p.name for p in args.dist.iterdir()} == set(PINS), 'Unexpected distribution files'
    source_checked = 0
    if args.source_root is not None:
        for name, expected in lock['project_files'].items():
            assert sha((args.source_root / name).read_bytes()) == expected, ('Source drift', name)
        actual = {str(p.relative_to(args.source_root)) for p in (args.source_root / 'src').rglob('*')
                  if p.is_file() and '__pycache__' not in p.parts and p.suffix != '.pyc'}
        assert actual == {n for n in lock['project_files'] if n.startswith('src/')}, 'SDK source inventory differs'
        source_checked = len(lock['project_files'])
    for name, expected in PINS.items():
        assert sha((args.dist / name).read_bytes()) == expected, name
    with zipfile.ZipFile(args.dist / 'spillway_guard-1.1.0-py3-none-any.whl') as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
        assert len(names) == len(set(names))
        assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts for n in names)
        wheel = {n: archive.read(n) for n in names}
    package = {n: b for n, b in wheel.items() if n.startswith('spillway_guard/')}
    assert {n: sha(b) for n, b in package.items()} == lock['package_members']
    assert 'spillway_guard/agentdojo/runner.py' not in package
    assert not any(n.endswith('.dist-info/entry_points.txt') for n in names)
    records = [n for n in names if n.endswith('.dist-info/RECORD')]
    assert len(records) == 1
    seen = set()
    for name, digest, size in csv.reader(io.StringIO(wheel[records[0]].decode())):
        assert name in wheel and name not in seen
        seen.add(name)
        if name == records[0]:
            assert not digest and not size
        else:
            expected = 'sha256=' + base64.urlsafe_b64encode(hashlib.sha256(wheel[name]).digest()).decode().rstrip('=')
            assert digest == expected and int(size) == len(wheel[name])
    assert seen == set(wheel)
    metadata_names = [n for n in names if n.endswith('.dist-info/METADATA')]
    assert len(metadata_names) == 1
    meta = BytesParser().parsebytes(wheel[metadata_names[0]])
    assert meta['Name'] == 'spillway-guard' and meta['Version'] == '1.1.0'
    source = {}
    with tarfile.open(args.dist / 'spillway_guard-1.1.0.tar.gz') as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and '..' not in path.parts and not member.issym() and not member.islnk()
            assert path.parts[0] == 'spillway_guard-1.1.0'
            if member.isfile():
                relative = str(PurePosixPath(*path.parts[1:]))
                assert relative not in source
                source[relative] = archive.extractfile(member).read()
    assert {n[4:]: b for n, b in source.items() if n.startswith('src/spillway_guard/')} == package
    assert re.findall(rb'(?m)^version = "([^"]+)"$', source['pyproject.toml']) == [b'1.1.0']
    assert {n: sha(source[n]) for n in lock['project_files']} == lock['project_files']
    assert all(PurePosixPath(n).parts[0] in {'src', 'README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'pyproject.toml', 'PKG-INFO'} for n in source)
    result = {
        'status': 'ROOT_FROZEN_110_ARCHIVE_VERIFICATION_PASS',
        'artifacts': {name: {'sha256': digest, 'bytes': (args.dist / name).stat().st_size} for name, digest in PINS.items()},
        'project_lock_sha256': LOCK_SHA, 'package_members': len(package),
        'frozen_project_files_verified': source_checked,
        'excluded_benchmark_runner': 'spillway_guard/agentdojo/runner.py',
        'RECORD_and_sdist_source_parity': True,
        'SDK_code_imported': False, 'network_or_model_calls': 0,
        'new_performance_measured': False, 'publication_executed': False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
