#!/usr/bin/env python3
"""Destructive qualification ONLY inside the explicitly selected disposable GHA VM.

Importing this module and --plan have no effects. There is intentionally no
local override, alternate installation root, fake scanner, or validator bypass.
Compatible with Apple's bootstrap Python 3.9; runtime tests use protected 3.11.
"""
import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import tarfile
import threading
import time
import xml.etree.ElementTree as ET

ROOT = Path('/Library/NmapUIQualification')
TOOLS = ROOT / 'toolchain'
PYTHON_PREFIX = ROOT / 'python'
PYTHON = PYTHON_PREFIX / 'bin/python3.11'
SOURCE = ROOT / 'source'
RECEIPTS = ROOT / 'receipts'
DATA = Path('/Library/Application Support/NmapUI')
LOGS = Path('/Library/Logs/NmapUI')
INSTALL = Path('/usr/local/lib/nmapui')
CURRENT = INSTALL / 'current'
PREVIOUS = INSTALL / 'previous'
LABEL = 'system/com.techmore.nmapui'
PLIST = Path('/Library/LaunchDaemons/com.techmore.nmapui.plist')
WRAPPER = Path('/usr/local/bin/nmapui-run')
HELPER = Path('/usr/local/libexec/nmapui-privileged-scanner')
SUDOERS = Path('/etc/sudoers.d/nmapui')
ASSETS = Path('/usr/local/share/nmapui')
TOOL_LINKS = [Path('/usr/local/bin/nmap'), Path('/usr/local/bin/arp-scan')]
BRANCH = 'refs/heads/codex/macos-installed-qualification-2026-10-25'
MANIFEST = Path(__file__).with_name('macos_qualification_sources.json')


def require_disposable_context(environment, system, machine):
    required = {
        'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
        'RUNNER_OS': 'macOS', 'GITHUB_REPOSITORY': 'techmore/TM-NmapUI',
        'GITHUB_REF': BRANCH, 'NMAPUI_DISPOSABLE_MAC_QUALIFICATION': '1',
    }
    if system != 'Darwin' or machine != 'arm64':
        raise RuntimeError('Only the selected disposable macOS arm64 VM may run this harness')
    if any(environment.get(key) != value for key, value in required.items()):
        raise RuntimeError('Missing explicit GitHub-hosted disposable qualification guards')
    if environment.get('GITHUB_EVENT_NAME') not in ('push', 'workflow_dispatch'):
        raise RuntimeError('Qualification never runs for pull_request events')
    if not re.fullmatch(r'[0-9]+', environment.get('GITHUB_RUN_ID', '')):
        raise RuntimeError('Missing workflow run identity')
    if not re.fullmatch(r'[0-9a-f]{40}', environment.get('GITHUB_SHA', '')):
        raise RuntimeError('Missing immutable harness commit identity')
    if not re.fullmatch(r'[0-9a-f]{40}', environment.get('NMAPUI_QUALIFIED_SOURCE', '')):
        raise RuntimeError('Runtime source must be an immutable commit SHA')



def require_disposable_host(environment, system, machine, uid):
    if uid != 0:
        raise RuntimeError('Provisioning requires root in the guarded disposable VM')
    require_disposable_context(environment, system, machine)


def inventory_entry(path):
    entry = {'path': str(path), 'exists': os.path.lexists(path)}
    if not entry['exists']:
        return entry
    details = path.lstat()
    entry.update(uid=details.st_uid, gid=details.st_gid, mode=oct(stat.S_IMODE(details.st_mode)),
                 kind='symlink' if path.is_symlink() else 'directory' if path.is_dir() else 'file')
    if path.is_symlink():
        entry['link_target'] = os.readlink(path)
    elif path.is_file():
        digest = hashlib.sha256()
        try:
            with path.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    digest.update(chunk)
            entry['sha256'] = digest.hexdigest()
        except OSError as error:
            entry['sha256_unavailable'] = type(error).__name__
    result = subprocess.run(['/bin/ls', '-ldeO@', str(path)], capture_output=True, text=True, timeout=15)
    entry['flags_acls_xattr_sizes'] = result.stdout
    if result.returncode:
        entry['acl_inspection_error'] = result.stderr
    return entry


def directory_inventory():
    paths = [Path(value) for value in [
        '/usr/local', '/usr/local/bin', '/usr/local/lib', '/usr/local/libexec', '/usr/local/share',
        '/usr/local/Homebrew', '/usr/local/Cellar', '/usr/local/opt', '/usr/local/bin/brew', '/opt/homebrew',
        '/Library', '/Library/Application Support', '/Library/Logs', '/Library/LaunchDaemons',
        '/etc', '/etc/sudoers.d']]
    entries = [inventory_entry(path) for path in paths]
    # These immediate child receipts permit a later approved shallow metadata
    # preparation to prove that child binaries, symlinks and ownership did not change.
    children = {}
    for path in paths[:5]:
        if path.is_dir() and not path.is_symlink():
            children[str(path)] = [inventory_entry(child) for child in sorted(path.iterdir())]
    return {'phase': 'inventory-only', 'qualification_executed': False,
            'harness_sha': os.environ.get('GITHUB_SHA'),
            'source_sha': os.environ.get('NMAPUI_QUALIFIED_SOURCE'),
            'system': platform.system(), 'architecture': platform.machine(),
            'entries': entries, 'immediate_children': children}


def write_diagnostic_inventory(output):
    require_disposable_context(os.environ, platform.system(), platform.machine())
    workspace = Path(os.environ['GITHUB_WORKSPACE']).resolve(strict=True)
    if output != workspace / 'diagnostics/macos-directory-inventory.json':
        raise RuntimeError('Diagnostic inventory must stay in this workflow workspace')
    output.parent.mkdir(exist_ok=True)
    output.write_text(json.dumps(directory_inventory(), indent=2, sort_keys=True) + '\n')
    print(output.read_text())


def run(arguments, **kwargs):
    return subprocess.run([str(item) for item in arguments], check=True, timeout=kwargs.pop('timeout', 180), **kwargs)


def capture(arguments):
    return run(arguments, capture_output=True, text=True).stdout


def require_absent(paths):
    for path in paths:
        if os.path.lexists(path):
            raise RuntimeError('Refusing pre-existing qualification/service target: ' + str(path))


def protected(path):
    """Check lexical and resolved ancestors; symlink targets receive the same check."""
    path = Path(os.path.abspath(path))
    for start in (path, path.resolve(strict=True)):
        for item in (start, *start.parents):
            info = item.lstat()
            if info.st_uid != 0 or (not stat.S_ISLNK(info.st_mode) and info.st_mode & 0o022):
                raise RuntimeError('Unprotected executable/state path: ' + str(item))


def protected_parent(path):
    candidate = Path(path).parent
    while not candidate.exists():
        candidate = candidate.parent
    protected(candidate)



def require_launchd_absent():
    existing = subprocess.run(['/bin/launchctl', 'print', LABEL], capture_output=True, text=True, timeout=15)
    if existing.returncode == 0:
        raise RuntimeError('Refusing existing NmapUI system LaunchDaemon')
    # Neither a missing executable nor a permission error proves service absence.
    if not re.search(r'(Could not find service|Could not find specified service)', existing.stderr, re.I):
        raise RuntimeError('Cannot establish launchd service absence: ' + existing.stderr)


def assert_initial_install_failure_restored():
    # Even when install never returns success, its rollback is an assertion,
    # not an assumption. Do not boot out a partially identified service.
    require_absent([CURRENT, PREVIOUS, PLIST, WRAPPER, HELPER, SUDOERS])
    require_launchd_absent()
    receipt('initial-install-failure-restored', {'loaded_service': False, 'active_artifacts': False})


def preflight(source):
    require_absent([ROOT, INSTALL, PLIST, WRAPPER, HELPER, SUDOERS, DATA, LOGS, ASSETS, *TOOL_LINKS])
    require_launchd_absent()
    for path in [ROOT, INSTALL, PLIST, WRAPPER, HELPER, SUDOERS, DATA, LOGS, ASSETS, *TOOL_LINKS]:
        protected_parent(path)
    actual = capture(['/usr/bin/git', '-C', source, 'rev-parse', 'HEAD']).strip()
    if actual != os.environ['NMAPUI_QUALIFIED_SOURCE']:
        raise RuntimeError('Source checkout does not match the immutable qualification pin')
    if capture(['/usr/bin/git', '-C', source, 'status', '--porcelain']).strip():
        raise RuntimeError('Runtime source checkout must be clean')


def receipt(name, value):
    RECEIPTS.mkdir(mode=0o755, parents=True, exist_ok=True)
    path = RECEIPTS / (name + '.json')
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + '\n')
    path.chmod(0o644)


def extract_verified(archive, destination, expected_hash):
    if hashlib.sha256(archive.read_bytes()).hexdigest() != expected_hash:
        raise RuntimeError('Source archive SHA256 mismatch: ' + archive.name)
    with tarfile.open(archive) as stream:
        for member in stream.getmembers():
            path = Path(member.name)
            if path.is_absolute() or '..' in path.parts or not (member.isdir() or member.isfile()):
                raise RuntimeError('Unsafe source archive member: ' + member.name)
        stream.extractall(destination)


def harden_tree(root):
    for path in [root, *root.rglob('*')]:
        if path.is_symlink():
            protected(path)
        elif path.is_dir():
            path.chmod(0o755)
        else:
            path.chmod(0o755 if path.stat().st_mode & 0o111 else 0o644)
        protected(path)


def load_stager():
    spec = importlib.util.spec_from_file_location('qualification_stager', SOURCE / 'packaging/stage_runtime.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def provision(source):
    preflight(source)
    ROOT.mkdir(mode=0o755)
    (ROOT / 'owner.json').write_text(json.dumps({'run': os.environ['GITHUB_RUN_ID'], 'source': os.environ['NMAPUI_QUALIFIED_SOURCE']}))
    (ROOT / 'owner.json').chmod(0o600)
    downloads, builds = ROOT / 'downloads', ROOT / 'build'
    downloads.mkdir(); builds.mkdir()
    manifest = json.loads(MANIFEST.read_text())
    shutil.copytree(source, SOURCE, symlinks=True, ignore=shutil.ignore_patterns('.git', '.venv', '__pycache__', '*.pyc'))
    # Copy the harness separately; the qualified runtime remains the pinned SHA.
    shutil.copy2(__file__, ROOT / 'harness.py')
    shutil.copy2(MANIFEST, ROOT / MANIFEST.name)
    env = {'PATH': '/usr/bin:/bin:/usr/sbin:/sbin', 'HOME': '/var/root', 'CC': '/usr/bin/clang',
           'CXX': '/usr/bin/clang++', 'PKG_CONFIG': '/usr/bin/false',
           'SDKROOT': capture(['/usr/bin/xcrun', '--show-sdk-path']).strip()}
    licenses = RECEIPTS / 'licenses'; licenses.mkdir(parents=True)
    for name, entry in manifest.items():
        archive = downloads / entry['url'].rsplit('/', 1)[1]
        run(['/usr/bin/curl', '--fail', '--location', '--proto', '=https', '--proto-redir', '=https',
             '--tlsv1.2', '--max-time', '180', '--max-filesize', '104857600', entry['url'], '-o', archive])
        extract_verified(archive, builds, entry['sha256'])
        tree = builds / entry['directory']
        license_dir = licenses / name; license_dir.mkdir()
        required_license = tree / entry['license']
        if not required_license.is_file():
            raise RuntimeError('Missing upstream license: ' + str(required_license))
        for path in tree.rglob('*'):
            if path.is_file() and any(token in path.name.upper() for token in ('LICENSE', 'COPYING', 'COPYRIGHT')):
                target = license_dir / path.relative_to(tree)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(path, target)
    receipt('source-provenance', manifest)
    jobs = str(min(os.cpu_count() or 2, 4))

    def build(name, configure, extra=None, install_target='install'):
        directory = builds / manifest[name]['directory']
        build_env = {**env, **(extra or {})}
        run(configure, cwd=directory, env=build_env)
        run(['/usr/bin/make', '-j' + jobs], cwd=directory, env=build_env, timeout=1800)
        run(['/usr/bin/make', install_target], cwd=directory, env=build_env, timeout=600)

    openssl = ROOT / 'openssl'
    build('openssl', ['./Configure', 'no-shared', '--prefix=' + str(openssl), '--openssldir=' + str(openssl / 'ssl')], install_target='install_sw')
    flags = {'CPPFLAGS': '-I' + str(openssl / 'include'), 'LDFLAGS': '-L' + str(openssl / 'lib')}
    build('python', ['./configure', '--prefix=' + str(PYTHON_PREFIX), '--disable-shared',
                     '--with-openssl=' + str(openssl), '--with-openssl-rpath=no', '--with-ensurepip=install'], flags)
    build('libpcap', ['./configure', '--prefix=' + str(TOOLS), '--disable-shared'])
    build('arp-scan', ['./configure', '--prefix=' + str(TOOLS)],
          {'CPPFLAGS': '-I' + str(TOOLS / 'include'), 'LDFLAGS': '-L' + str(TOOLS / 'lib')})
    build('nmap', ['./configure', '--prefix=' + str(TOOLS), '--with-openssl=' + str(openssl),
                   '--with-libpcap=included', '--with-libpcre=included', '--with-libz=included',
                   '--with-libssh2=included', '--with-libdnet=included', '--with-liblua=included',
                   '--with-liblinear=included', '--without-zenmap', '--without-ndiff'], flags)
    # GUI/Ndiff are not scanner capabilities. TLS, SSH, Lua/NSE and raw capture
    # remain enabled and their actual compiled support is recorded below.
    run([PYTHON, '-m', 'venv', SOURCE / '.venv'], env=env)
    run([SOURCE / '.venv/bin/python', '-m', 'pip', 'install', '-r', SOURCE / 'requirements.txt'], env=env, timeout=900)
    harden_tree(ROOT)
    for link in TOOL_LINKS:
        protected_parent(link)
        require_absent([link])
        link.symlink_to(TOOLS / 'bin' / link.name)
    stager = load_stager()
    for executable in ['/bin/bash', '/usr/bin/python3', '/usr/sbin/traceroute', '/usr/bin/xsltproc', *TOOL_LINKS, PYTHON]:
        stager.verify_root_executable(Path(executable))
    stager.verify_root_interpreter(SOURCE / '.venv/bin/python')
    stager.verify_root_nmap_data_dir(TOOLS / 'share/nmap')
    version = capture([TOOLS / 'bin/nmap', '--version'])
    for capability in ['liblua', 'openssl', 'libssh2', 'libpcap']:
        if capability not in version.lower():
            raise RuntimeError('Required compiled Nmap support missing: ' + capability)
    receipt('toolchain', {'nmap': version, 'python': capture([PYTHON, '--version']),
                          'arp_scan': capture([TOOLS / 'bin/arp-scan', '--version'])})
    # Re-enter with protected Python, never the hosted setup-python interpreter.
    env.update({key: value for key, value in os.environ.items()
                if key.startswith(('GITHUB_', 'RUNNER_', 'NMAPUI_QUALIFIED_', 'NMAPUI_DISPOSABLE_'))})
    service_python = SOURCE / '.venv/bin/python'
    os.execve(str(service_python), [str(service_python), str(ROOT / 'harness.py'), '--exercise'], env)


def macho_dependencies(output):
    return [line.strip().split(' (', 1)[0] for line in output.splitlines()[1:] if line[:1].isspace()]


def macho_loads(output):
    dependencies = []
    for block in re.split(r'Load command \d+', output):
        if re.search(r'cmd LC_(LOAD_DYLIB|LOAD_WEAK_DYLIB|REEXPORT_DYLIB|LAZY_LOAD_DYLIB|LOAD_UPWARD_DYLIB)\s', block):
            match = re.search(r'\n\s*name (.*?) \(offset \d+\)', block)
            if not match:
                raise RuntimeError('Malformed Mach-O library load command')
            dependencies.append(match.group(1))
    return dependencies


def macho_rpaths(output):
    return re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset \d+\)', output)


def expand_loader(value, binary, executable):
    if value.startswith('@loader_path/'):
        return binary.parent / value[len('@loader_path/'):]
    if value.startswith('@executable_path/'):
        return executable.parent / value[len('@executable_path/'):]
    if value.startswith('/'):
        return Path(value)
    raise RuntimeError('Unsupported or nonabsolute Mach-O path: ' + value)


def resolve_dependency(value, binary, executable, rpaths):
    if value.startswith('@rpath/'):
        candidates = [expand_loader(item, binary, executable) / value[len('@rpath/'):]
                      for item in rpaths]
        # dyld selects the first existing candidate. Audit that exact path.
        for candidate in candidates:
            if candidate.exists():
                return candidate
        raise RuntimeError('Unresolved Mach-O rpath: ' + value)
    return expand_loader(value, binary, executable)


def audit_python(venv):
    """Resolve legitimate protected wheel-relative libraries without changing policy.

    Existing tool validators stay unchanged; Python wheels commonly use
    @loader_path for their private dylibs. Resolve and protect these paths,
    rather than either banning them or silently skipping their dependencies.
    """
    stager = load_stager()
    stager.verify_root_interpreter(venv / 'bin/python')
    if 'include-system-site-packages = false' not in (venv / 'pyvenv.cfg').read_text():
        raise RuntimeError('Service virtualenv inherits external site-packages')
    identity = json.loads(capture([venv / 'bin/python', '-I', '-c',
        'import json,sys; print(json.dumps(dict(base_prefix=sys.base_prefix, prefix=sys.prefix, path=sys.path)))']))
    if Path(identity['base_prefix']).resolve() != PYTHON_PREFIX.resolve(strict=True):
        raise RuntimeError('Service Python base prefix does not match the protected build')
    for entry in identity['path']:
        if Path(entry).exists(): protected(Path(entry))
        else: protected_parent(Path(entry))
    seen = set()
    executable = PYTHON.resolve(strict=True)
    inventory = []

    def inspect(binary, inherited=()):
        protected(binary)
        binary = binary.resolve(strict=True)
        if binary in seen:
            return
        seen.add(binary)
        commands = capture(['/usr/bin/otool', '-l', binary])
        rpaths = [*[str(expand_loader(item, binary, executable))
                     for item in macho_rpaths(commands)], *inherited]
        dependencies = macho_loads(commands)
        inventory.append({'binary': str(binary), 'dependencies': dependencies,
                          'sha256': hashlib.sha256(binary.read_bytes()).hexdigest()})
        for dependency in dependencies:
            # Apple dyld shared-cache libraries may not have on-disk files.
            if dependency.startswith(('/usr/lib/', '/System/Library/')):
                continue
            path = resolve_dependency(dependency, binary, executable, rpaths)
            inspect(path, rpaths)

    extensions, libraries = [], []
    for root in [PYTHON_PREFIX, ROOT / 'openssl', venv]:
        for path in [root, *root.rglob('*')]:
            protected(path)
            if path.is_file() and path.suffix == '.so': extensions.append(path)
            if path.is_file() and path.suffix == '.dylib': libraries.append(path)
    inspect(executable)
    # Walk actual extension roots before remaining dylibs, so dependent loads
    # inherit their real owner's expanded rpaths. LC_ID_DYLIB is not a load.
    for extension in extensions: inspect(extension)
    for library in libraries: inspect(library)
    return inventory


def wait_until(description, predicate, timeout=60):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.25)
    raise RuntimeError('Timed out: ' + description)


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0))
        return listener.getsockname()[1]


def verify_owner():
    protected(ROOT / 'owner.json')
    owner = json.loads((ROOT / 'owner.json').read_text())
    if owner != {'run': os.environ['GITHUB_RUN_ID'], 'source': os.environ['NMAPUI_QUALIFIED_SOURCE']}:
        raise RuntimeError('Qualification ownership receipt does not match this job')


def installer(*arguments, expect_success=True):
    verify_owner()
    result = subprocess.run(['/bin/bash', str(SOURCE / 'packaging/macos/install-daemon.sh'), *arguments],
                            cwd=SOURCE, timeout=420, check=False)
    if expect_success != (result.returncode == 0):
        raise RuntimeError('Unexpected installer result: ' + str(result.returncode))


def ready(port, release):
    import http.client
    try:
        connection = http.client.HTTPConnection('127.0.0.1', port, timeout=3)
        try:
            connection.request('GET', '/api/health/ready')
            response = connection.getresponse()
            payload = json.load(response)
            return (response.status == 200 and payload.get('ready') is True and
                    payload.get('release_id') == (release / 'release_id').read_text().strip())
        finally:
            connection.close()
    except (OSError, ValueError):
        return False


def launchd_pid():
    output = capture(['/bin/launchctl', 'print', LABEL])
    match = re.search(r'^\s*pid = (\d+)$', output, re.M)
    return int(match.group(1)) if match else 0


def verify_installed(port, phase):
    stager = load_stager()
    release = CURRENT.resolve(strict=True)
    if release.parent != INSTALL / 'releases':
        raise RuntimeError('Installed release escaped the managed release directory')
    for path in [release / 'app.py', release / 'release_id', PLIST, WRAPPER, HELPER, SUDOERS]:
        stager.verify_root_file(path)
    stager.verify_root_directory(release)
    for path in [DATA, DATA / 'data', LOGS]:
        protected(path)
        if stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise RuntimeError('Mutable state directory is not private: ' + str(path))
    credentials = DATA / 'credentials.env'
    protected(credentials)
    if stat.S_IMODE(credentials.stat().st_mode) != 0o600:
        raise RuntimeError('Service credentials are not private')
    wait_until('release ready: ' + phase, lambda: ready(port, release), timeout=60)
    pid = launchd_pid()
    uid = capture(['/bin/ps', '-p', str(pid), '-o', 'uid=']).strip()
    if not pid or uid != '0':
        raise RuntimeError('System launchd backend is not running as root')
    listeners = capture(['/usr/sbin/lsof', '-nP', '-iTCP:' + str(port), '-sTCP:LISTEN'])
    if '127.0.0.1:' + str(port) not in listeners or '*:' + str(port) in listeners:
        raise RuntimeError('Service is not bound exclusively to the requested loopback port')
    import plistlib
    plist = plistlib.loads(PLIST.read_bytes())
    if plist.get('UserName') != 'root' or plist.get('ProgramArguments') != [str(WRAPPER)] or not plist.get('KeepAlive') or not plist.get('RunAtLoad'):
        raise RuntimeError('Unexpected installed system LaunchDaemon configuration')
    inventory = audit_python(release / '.venv')
    receipt('installed-' + phase, {'release': str(release), 'release_id': (release / 'release_id').read_text().strip(),
                                 'pid': pid, 'uid': int(uid), 'port': port, 'listener': listeners,
                                 'python_dependency_inventory': inventory})
    return release


def auth_and_api_workflow(port, password):
    import requests
    import socketio
    base_url = 'http://127.0.0.1:' + str(port)
    for endpoint in ['/api/runtime/status', '/api/settings', '/api/socket-token']:
        response = requests.get(base_url + endpoint, timeout=5)
        if response.status_code != 401:
            raise RuntimeError('Strict HTTP authentication did not protect ' + endpoint)
    session = requests.Session()
    session.auth = ('qualification', password)
    response = session.get(base_url + '/api/runtime/status', timeout=5)
    response.raise_for_status()
    if 'no-store' not in response.headers.get('Cache-Control', ''):
        raise RuntimeError('Runtime status is cacheable')
    settings = session.get(base_url + '/api/settings', timeout=5)
    settings.raise_for_status()
    value = settings.json()
    value.setdefault('scan_rules', {})['scan_only_mode'] = True
    # This existing scan-only setting suppresses ARP. The quick workflow still
    # performs its normal root service scan; original XML below must prove SYN.
    # Its loopback-port scope is separate from the single-port standalone proof.
    saved = session.post(base_url + '/api/settings', json=value, timeout=5)
    saved.raise_for_status()
    if not saved.json().get('success'):
        raise RuntimeError('Could not configure the owned loopback discovery workflow')
    token_response = session.get(base_url + '/api/socket-token', timeout=5)
    token_response.raise_for_status()
    anonymous = socketio.Client(handle_sigint=False, reconnection=False, request_timeout=5)
    try:
        anonymous.connect(base_url, auth={'token': token_response.json()['token']},
                          transports=['websocket'], wait_timeout=5)
    except socketio.exceptions.ConnectionError:
        pass
    else:
        anonymous.disconnect()
        raise RuntimeError('Socket token alone bypassed strict socket authentication')
    client = socketio.Client(handle_sigint=False, reconnection=False, request_timeout=5)
    jobs, hosts, errors, xml_chunks = [], [], [], []
    condition = threading.Condition()
    def record(collection, packet):
        with condition:
            collection.append(packet)
            condition.notify_all()
    client.on('job_status', lambda packet, collection=jobs: record(collection, packet))
    client.on('quickscan_results', lambda packet, collection=hosts: record(collection, packet))
    client.on('scan_error', lambda packet, collection=errors: record(collection, packet))
    client.on('scan_xml_chunk', lambda packet, collection=xml_chunks: record(collection, packet))
    header = 'Basic ' + base64.b64encode(('qualification:' + password).encode()).decode()
    try:
        client.connect(base_url, auth={'token': token_response.json()['token']},
                       headers={'Authorization': header}, transports=['websocket'], wait_timeout=10)
        client.emit('start_scan', {'target': '127.0.0.1', 'skip_host_discovery': True})
        # Socket.IO can dispatch handlers concurrently. A terminal callback
        # alone does not establish that earlier XML/results callbacks ran.
        with condition:
            if not condition.wait_for(lambda: api_evidence_ready(jobs, hosts, xml_chunks), timeout=160):
                raise RuntimeError('Timed out awaiting complete installed API evidence')
            jobs, hosts, errors, xml_chunks = list(jobs), list(hosts), list(errors), list(xml_chunks)
        completed = [job for job in jobs if job.get('job_type') == 'scan' and job.get('status') == 'completed']
        if errors or not completed or not hosts or hosts[-1].get('hosts_up') != 1:
            raise RuntimeError('Installed API workflow did not complete the real loopback discovery')
        observed = {job.get('source_job_id') for job in jobs if job.get('job_type') == 'scan' and job.get('source_job_id')}
        if len(observed) != 1:
            raise RuntimeError('API workflow did not retain one observed source identity')
        xml = verified_api_xml(xml_chunks)
        if completed[-1].get('details', {}).get('incomplete_hosts'):
            raise RuntimeError('Installed API loopback service scan was incomplete')
        (RECEIPTS / 'installed-api-scan.xml').write_bytes(xml)
        receipt('installed-api-workflow', {'target': '127.0.0.1', 'source_job_id': observed.pop(),
                                         'status': 'completed', 'hosts_up': hosts[-1]['hosts_up'],
                                         'mode': 'canonical loopback discovery and real service scan; ARP/enrichment disabled',
                                         'technique': ET.fromstring(xml).find('./scaninfo').get('type')})
    finally:
        if client.connected:
            client.disconnect()




def api_evidence_ready(jobs, hosts, chunks):
    terminal = [job for job in jobs if job.get('job_type') == 'scan' and job.get('source_job_id')
                and job.get('status') in ('completed', 'failed', 'cancelled')]
    if not terminal:
        return False
    if any(job.get('status') != 'completed' for job in terminal):
        return True  # Report real workflow failure immediately, without XML waits.
    if not hosts or not chunks:
        return False
    count = chunks[0].get('chunk_count')
    # Malformed evidence proceeds to strict validation, never a success receipt.
    return not isinstance(count, int) or not 1 <= count <= 525 or len(chunks) >= count


def verified_api_xml(chunks):
    if not chunks or any(chunk.get('target') != '127.0.0.1' for chunk in chunks):
        raise RuntimeError('Missing or non-loopback API XML evidence')
    first = chunks[0]
    count = first.get('chunk_count')
    if not isinstance(count, int) or not 1 <= count <= 525 or len(chunks) != count:
        raise RuntimeError('Incomplete or oversized API XML chunk set')
    ordered = sorted(chunks, key=lambda chunk: chunk.get('chunk_index', -1))
    if [chunk.get('chunk_index') for chunk in ordered] != list(range(count)):
        raise RuntimeError('Duplicated or missing API XML chunk index')
    if any(chunk.get('sha256') != first.get('sha256') or chunk.get('byte_count') != first.get('byte_count') or chunk.get('chunk_count') != count for chunk in chunks):
        raise RuntimeError('Mixed API XML observations')
    xml = ''.join(chunk['xml'] for chunk in ordered).encode('utf-8')
    if len(xml) > 16 * 1024 * 1024 or len(xml) != first.get('byte_count') or hashlib.sha256(xml).hexdigest() != first.get('sha256'):
        raise RuntimeError('API XML digest/length mismatch')
    document = ET.fromstring(xml)
    addresses = document.findall('./host/address[@addrtype="ipv4"]')
    summary = document.find('./runstats/finished')
    scan = document.find('./scaninfo')
    if len(addresses) != 1 or addresses[0].get('addr') != '127.0.0.1' or summary is None or summary.get('exit') != 'success':
        raise RuntimeError('API XML does not establish a successful loopback-only scan')
    if scan is None or scan.get('type') != 'syn':
        raise RuntimeError('Installed root workflow did not produce real SYN service-scan evidence')
    return xml


def standalone_syn():
    # The listener, scanner target, and output file are all owned by this job.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen()
        port = listener.getsockname()[1]
        output = RECEIPTS / 'standalone-syn.xml'
        run([TOOLS / 'bin/nmap', '-n', '-Pn', '-sS', '-p', str(port), '--host-timeout', '15s',
             '-oX', output, '127.0.0.1'], timeout=25)
        xml = ET.parse(output).getroot()
        if xml.find('./scaninfo').get('type') != 'syn' or xml.find('./host/address').get('addr') != '127.0.0.1':
            raise RuntimeError('Standalone scan did not use SYN exclusively against owned loopback')
        scanned_port = xml.find('./host/ports/port')
        if scanned_port.get('portid') != str(port) or scanned_port.find('state').get('state') != 'open':
            raise RuntimeError('Standalone SYN did not observe the owned listener')
        receipt('standalone-syn', {'target': '127.0.0.1', 'port': port, 'technique': 'syn', 'state': 'open'})


def verify_artifact_restoration(release):
    for installed, archived in [(WRAPPER, 'nmapui-run'), (HELPER, 'nmapui-privileged-scanner'),
                                (SUDOERS, 'nmapui.sudoers'), (PLIST, 'com.techmore.nmapui.plist')]:
        if installed.read_bytes() != (release / 'service-artifacts' / archived).read_bytes():
            raise RuntimeError('Failed transaction did not restore ' + str(installed))


def exercise():
    verify_owner()
    if Path(sys.executable).resolve() != PYTHON.resolve(strict=True):
        raise RuntimeError('Lifecycle exercise must run under the protected base Python')
    receipt('python-source-closure', audit_python(SOURCE / '.venv'))
    port = free_port()
    # Refuse collisions immediately before configuration; installer repeats it.
    collision = subprocess.run(['/usr/sbin/lsof', '-nP', '-iTCP:' + str(port), '-sTCP:LISTEN', '-t'], capture_output=True, timeout=10)
    if collision.returncode != 1:
        raise RuntimeError('Chosen service port is not provably free')
    DATA.mkdir(mode=0o700)
    owner_file = DATA / '.qualification-owner'
    owner_file.write_text(os.environ['GITHUB_RUN_ID']); owner_file.chmod(0o600)
    import secrets
    password = secrets.token_hex(24)
    credentials = {
        'NMAPUI_DATA_DIR': str(DATA / 'data'), 'NMAPUI_LOG_DIR': str(LOGS),
        'NMAPUI_HOST': '127.0.0.1', 'NMAPUI_PORT': str(port), 'NMAPUI_TRUST_LOCAL_UI': 'false',
        'NMAPUI_COOKIE_SECURE': 'false', 'NMAPUI_STARTUP_TRACEROUTE': 'false',
        'NMAPUI_ENABLE_NETWORK_FINGERPRINT': 'false', 'NMAPUI_ENABLE_UPDATE_CHECK': 'false',
        'NMAPUI_ENABLE_VULNERS': 'false', 'NMAPUI_PRIVILEGED_ASSETS': str(ASSETS),
        'PLAYWRIGHT_BROWSERS_PATH': str(ASSETS / 'playwright-browsers'),
        'NMAPUI_USERNAME': 'qualification', 'NMAPUI_PASSWORD': password,
    }
    credentials_file = DATA / 'credentials.env'
    credentials_file.write_text(''.join(key + '=' + value + '\n' for key, value in credentials.items()))
    credentials_file.chmod(0o600)
    credentials_hash = hashlib.sha256(credentials_file.read_bytes()).hexdigest()
    installed = False
    try:
        try:
            installer()
        except Exception:
            assert_initial_install_failure_restored()
            raise
        installed = True
        first = verify_installed(port, 'initial')
        standalone_syn()
        auth_and_api_workflow(port, password)
        # Reuse the real authenticated browser/session/WebSocket regression.
        env = {**os.environ, 'PLAYWRIGHT_BROWSERS_PATH': str(ASSETS / 'playwright-browsers'),
               'NMAPUI_TEST_INSTALLED_SERVICE_URL': 'http://127.0.0.1:' + str(port),
               'NMAPUI_TEST_INSTALLED_SERVICE_USERNAME': 'qualification',
               'NMAPUI_TEST_INSTALLED_SERVICE_PASSWORD': password}
        run([first / '.venv/bin/python', '-m', 'pytest', '-q', 'tests/test_production_server.py::test_installed_service_requires_session_and_accepts_websocket'], cwd=SOURCE, env=env, timeout=90)
        # Recovery uses the actual installed SQLite store and real supervisor.
        sys.path.insert(0, str(first))
        from nmapui.runtime_db import create_runtime_state_store
        database = DATA / 'data/runtime.sqlite3'
        store = create_runtime_state_store(str(database))
        store.upsert_job(job_id='qualification-interrupted', owner_sid='qualification', job_type='scan', status='running', payload={'target': '127.0.0.1'})
        old_pid = launchd_pid()
        command = capture(['/bin/ps', '-p', str(old_pid), '-o', 'command=']) if old_pid > 1 else ''
        if old_pid <= 1 or 'gunicorn' not in command or str(CURRENT) not in command:
            raise RuntimeError('Refusing to kill a process without the managed Gunicorn identity')
        os.kill(old_pid, 9)
        wait_until('launchd respawn with a new PID', lambda: launchd_pid() not in (0, old_pid), timeout=45)
        verify_installed(port, 'crash-recovery')
        recovered = store.get_job('qualification-interrupted')
        if not recovered or recovered['status'] != 'interrupted':
            raise RuntimeError('Crash recovery did not interrupt the persisted active job')
        receipt('crash-recovery', {'old_pid': old_pid, 'new_pid': launchd_pid(), 'status': recovered['status']})
        sentinel = DATA / 'data/qualification-sentinel'
        sentinel.write_bytes(b'preserved qualification data\n'); sentinel.chmod(0o600)
        installer()
        second = verify_installed(port, 'upgrade')
        if second == first or PREVIOUS.resolve() != first:
            raise RuntimeError('Upgrade did not record both immutable release identities')
        installer('--rollback')
        if CURRENT.resolve() != first or PREVIOUS.resolve() != second:
            raise RuntimeError('Rollback did not swap both release links')
        verify_installed(port, 'rollback')
        broken = b"raise RuntimeError('Intentional disposable qualification startup failure')\n"
        wsgi = SOURCE / 'nmapui/wsgi.py'; original = wsgi.read_bytes()
        try:
            wsgi.write_bytes(broken)
            installer(expect_success=False)
        finally:
            wsgi.write_bytes(original)
        if CURRENT.resolve() != first or PREVIOUS.resolve() != second:
            raise RuntimeError('Failed upgrade changed managed links')
        verify_installed(port, 'failed-upgrade-restored'); verify_artifact_restoration(first)
        wsgi = second / 'nmapui/wsgi.py'; original = wsgi.read_bytes()
        try:
            wsgi.write_bytes(broken)
            installer('--rollback', expect_success=False)
        finally:
            wsgi.write_bytes(original)
        if CURRENT.resolve() != first or PREVIOUS.resolve() != second:
            raise RuntimeError('Failed rollback changed managed links')
        verify_installed(port, 'failed-rollback-restored'); verify_artifact_restoration(first)
        installer('--uninstall')
        installed = False
        require_launchd_absent()
        require_absent([PLIST, WRAPPER, HELPER, SUDOERS, CURRENT, PREVIOUS])
        if sentinel.read_bytes() != b'preserved qualification data\n' or not first.is_dir() or not second.is_dir():
            raise RuntimeError('Uninstall removed data or immutable release archives')
        if hashlib.sha256(credentials_file.read_bytes()).hexdigest() != credentials_hash:
            raise RuntimeError('Lifecycle changed the original credentials')
        receipt('result', {'passed': True, 'source_sha': os.environ['NMAPUI_QUALIFIED_SOURCE'],
                           'harness_sha': os.environ['GITHUB_SHA'],
                           'first_release': str(first), 'second_release': str(second),
                           'strict_auth': True, 'data_preserved': True, 'credentials_preserved': True,
                           'reboot_physical_soak_signing_notarization': 'not tested'})
    finally:
        if installed:
            # Cleanup is authorized only by the protected marker made before
            # install, and the unchanged installed-artifact validators.
            verify_owner(); protected(owner_file)
            if owner_file.read_text() != os.environ['GITHUB_RUN_ID']:
                raise RuntimeError('Refusing cleanup of an unowned service')
            installer('--uninstall')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--exercise', action='store_true')
    parser.add_argument('--inventory-output', type=Path, help='Read-only hosted directory/ACL inventory; no provisioning')
    parser.add_argument('--plan', action='store_true', help='Print fixed plan without platform checks or effects')
    arguments = parser.parse_args()
    if arguments.plan:
        print(json.dumps({'root': str(ROOT), 'label': LABEL, 'branch': BRANCH,
                          'sources': json.loads(MANIFEST.read_text()),
                          'effects': 'ONLY guarded disposable GHA macOS VM; no local execution supported'}, indent=2))
        return
    if arguments.inventory_output:
        write_diagnostic_inventory(arguments.inventory_output)
        return
    require_disposable_host(os.environ, platform.system(), platform.machine(), os.geteuid())
    if arguments.exercise:
        exercise()
    elif arguments.source:
        provision(arguments.source.resolve(strict=True))
    else:
        parser.error('--source is required for initial provisioning')


if __name__ == '__main__':
    main()
