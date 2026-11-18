"""Read-only verification of the frozen final101 distribution archives.

This checks artifacts, not publication authorization or model performance.
It never imports the SDK, extracts archive code or contacts a service.
"""
import argparse
import base64
import csv
from email.parser import BytesParser
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

PINS = {
    'spillway_guard-1.0.1-py3-none-any.whl': 'f93d56ecb11890af5a8381bd6ef1de916803e61f94137992b7e435ad93ff5c21',
    'spillway_guard-1.0.1.tar.gz': '77a26f53b42dbe8fff208672d1faccbaa9f7c88c57ac86957585e40e9f1ab9eb',
}
LOCK_SHA = 'cc42dba9cd99bbca1655f7198b8e5082490a8e2f2572fe030c4eb4005fa500c5'


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
    assert lock['version'] == '1.0.1' and lock['package_count'] == 27
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
    with zipfile.ZipFile(args.dist / 'spillway_guard-1.0.1-py3-none-any.whl') as archive:
        names = [i.filename for i in archive.infolist() if not i.is_dir()]
        assert len(names) == len(set(names))
        assert all(not PurePosixPath(n).is_absolute() and '..' not in PurePosixPath(n).parts for n in names)
        wheel = {n: archive.read(n) for n in names}
    package = {n: b for n, b in wheel.items() if n.startswith('spillway_guard/')}
    assert {n: sha(b) for n, b in package.items()} == lock['package27_members']
    original = lock['baseline_P0_package27_members']
    differences = [n for n, b in package.items() if sha(b) != original[n]]
    assert differences == ['spillway_guard/__init__.py']
    before_version = package[differences[0]].replace(b'__version__ = "1.0.1"', b'__version__ = "1.0.1rc1"')
    assert sha(before_version) == original[differences[0]]
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
    assert meta['Name'] == 'spillway-guard' and meta['Version'] == '1.0.1'
    source = {}
    with tarfile.open(args.dist / 'spillway_guard-1.0.1.tar.gz') as archive:
        for member in archive.getmembers():
            path = PurePosixPath(member.name)
            assert not path.is_absolute() and '..' not in path.parts and not member.issym() and not member.islnk()
            assert path.parts[0] == 'spillway_guard-1.0.1'
            if member.isfile():
                relative = str(PurePosixPath(*path.parts[1:]))
                assert relative not in source
                source[relative] = archive.extractfile(member).read()
    assert {n[4:]: b for n, b in source.items() if n.startswith('src/spillway_guard/')} == package
    assert re.findall(rb'(?m)^version = "([^"]+)"$', source['pyproject.toml']) == [b'1.0.1']
    assert {n: sha(source[n]) for n in lock['project_files']} == lock['project_files']
    assert all(PurePosixPath(n).parts[0] in {'src', 'README.md', 'CHANGELOG.md', 'LICENSE', 'NOTICE', 'pyproject.toml', 'PKG-INFO'} for n in source)
    result = {
        'status': 'ROOT_FROZEN_FINAL101_ARCHIVE_VERIFICATION_PASS',
        'artifacts': {name: {'sha256': digest, 'bytes': (args.dist / name).stat().st_size} for name, digest in PINS.items()},
        'project_lock_sha256': LOCK_SHA, 'package_members': len(package),
        'frozen_project_files_verified': source_checked,
        'runtime_members': len(lock['runtime26_members']),
        'version_only_changed_path': differences[0], 'other_package_members_unchanged': 26,
        'RECORD_and_sdist_source_parity': True,
        'SDK_code_imported': False, 'network_or_model_calls': 0,
        'new_performance_measured': False, 'publication_executed': False,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
