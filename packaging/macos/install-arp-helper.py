#!/usr/bin/python3
"""Install an ARP-only helper for the existing per-user Mac scanner."""
import os
from pathlib import Path
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tempfile

BASE = Path('/Library/PrivilegedHelperTools/DaedalusARP')
HELPER = BASE / 'scan'
RULE = Path('/etc/sudoers.d/daedalus-arp')
SOURCE_TOOL = Path('/opt/homebrew/bin/arp-scan')
SOURCE_OUI = Path('/opt/homebrew/share/arp-scan/ieee-oui.txt')
CODE = r'''#!/usr/bin/python3
import ipaddress, os, re, stat, sys
from pathlib import Path
BASE = Path('/Library/PrivilegedHelperTools/DaedalusARP')
def run():
    if len(sys.argv) != 5 or sys.argv[1] != 'arp-scan' or sys.argv[3] != '--interface':
        raise ValueError('Expected arp-scan IPv4-CIDR --interface enN')
    network = ipaddress.ip_network(sys.argv[2], strict=False)
    if network.version != 4 or network.num_addresses > 4096 or not any(network.subnet_of(ipaddress.ip_network(n)) for n in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
        raise ValueError('Only bounded private IPv4 networks are supported')
    if not re.fullmatch(r'en[0-9]{1,3}', sys.argv[4]):
        raise ValueError('Only a local Ethernet/Wi-Fi interface is supported')
    for path in (BASE, BASE/'scan', BASE/'arp-scan', BASE/'ieee-oui.txt'):
        info=path.lstat()
        if path.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise ValueError('Helper files must be protected and root-owned')
    os.chdir(BASE)
    os.execve(str(BASE/'arp-scan'), ['arp-scan', str(network), '--interface', sys.argv[4], '--retry=2', '--timeout=500', '--ouifile='+str(BASE/'ieee-oui.txt'), '--macfile=/dev/null'], {'PATH':'/usr/bin:/bin:/usr/sbin:/sbin','HOME':'/var/root','LC_ALL':'C'})
try:
    run()
except (ValueError, OSError) as error:
    print('Daedalus ARP helper: '+str(error), file=sys.stderr)
    sys.exit(126)
'''

def main():
    if os.geteuid() != 0 or len(sys.argv) != 2:
        raise SystemExit('Run as administrator with the scanner username')
    username = sys.argv[1]
    if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_-]*', username) or pwd.getpwnam(username).pw_uid == 0:
        raise SystemExit('Expected a non-root scanner account')
    if not SOURCE_TOOL.is_file() or not SOURCE_OUI.is_file():
        raise SystemExit('Install arp-scan with Homebrew first')
    for parent in (BASE.parent, RULE.parent):
        info=parent.lstat()
        if parent.is_symlink() or info.st_uid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            raise SystemExit('Unsafe installation parent: '+str(parent))
    if BASE.is_symlink() or RULE.is_symlink():
        raise SystemExit('Refusing symlinked installation paths')
    BASE.mkdir(mode=0o755, exist_ok=True)
    os.chown(BASE,0,0);os.chmod(BASE,0o755)
    # Stage protected copies; never execute mutable Homebrew binaries via sudo.
    for source, name, mode in ((SOURCE_TOOL,'arp-scan',0o755),(SOURCE_OUI,'ieee-oui.txt',0o644)):
        destination=BASE/name
        if destination.is_symlink():raise SystemExit('Refusing symlinked helper asset')
        with tempfile.NamedTemporaryFile(dir=BASE,delete=False) as staged:
            with source.open('rb') as incoming:shutil.copyfileobj(incoming,staged)
            os.fchmod(staged.fileno(),mode);os.fchown(staged.fileno(),0,0)
        os.replace(staged.name,destination)
    with tempfile.NamedTemporaryFile(dir=BASE,delete=False) as staged:
        staged.write(CODE.encode());os.fchmod(staged.fileno(),0o755);os.fchown(staged.fileno(),0,0)
    os.replace(staged.name,HELPER)
    content=f'{username} ALL=(root) NOPASSWD: {HELPER}\n'
    with tempfile.NamedTemporaryFile(dir=RULE.parent,delete=False) as staged:
        staged.write(content.encode());os.fchmod(staged.fileno(),0o440);os.fchown(staged.fileno(),0,0)
    try:
        subprocess.run(['/usr/sbin/visudo','-cf',staged.name],check=True)
        os.replace(staged.name,RULE)
    finally:
        if os.path.exists(staged.name):os.unlink(staged.name)
    print('Installed ARP-only helper for '+username+'. Nmap and the web backend remain unprivileged.')

if __name__ == '__main__':main()
