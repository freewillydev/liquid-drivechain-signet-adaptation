#!/usr/bin/env python3
"""Bundle Windows or Linux executables with assets and non-system libraries."""
import argparse
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess


def pe_imports(path):
    data = path.read_bytes()
    offset = struct.unpack_from('<I', data, 0x3c)[0]
    if data[offset:offset + 4] != b'PE\0\0':
        raise ValueError('Not a Windows executable: ' + str(path))
    sections = struct.unpack_from('<H', data, offset + 6)[0]
    size = struct.unpack_from('<H', data, offset + 20)[0]
    optional = offset + 24
    magic = struct.unpack_from('<H', data, optional)[0]
    directories = optional + (112 if magic == 0x20b else 96)
    table = optional + size

    def file_offset(rva):
        for index in range(sections):
            section = table + index * 40
            virtual_size, address, raw_size, raw_offset = struct.unpack_from('<IIII', data, section + 8)
            if address <= rva < address + max(virtual_size, raw_size):
                return raw_offset + rva - address
        raise ValueError('Import RVA outside sections: ' + str(path))

    import_rva = struct.unpack_from('<I', data, directories + 8)[0]
    if not import_rva:
        return []
    position = file_offset(import_rva)
    names = []
    while any(data[position:position + 20]):
        name_rva = struct.unpack_from('<I', data, position + 12)[0]
        name = file_offset(name_rva)
        names.append(data[name:data.index(b'\0', name)].decode('ascii'))
        position += 20
    return names


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('binary', type=Path)
    parser.add_argument('--platform', choices=['windows', 'linux'], required=True)
    parser.add_argument('--library-dir', action='append', type=Path, default=[])
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--system-library-dir', type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    if output.exists():
        raise FileExistsError('Choose a new output folder: ' + str(output))
    executable_dir = output / 'bin'
    library_dir = executable_dir if args.platform == 'windows' else output / 'lib'
    executable_dir.mkdir(parents=True)
    library_dir.mkdir(exist_ok=True)
    name = 'elements-blue-current' + ('.exe' if args.platform == 'windows' else '')
    shutil.copy2(args.binary, executable_dir / name)
    shutil.copytree(root / 'assets', output / 'Resources/assets')
    shutil.copy2(root / 'README.md', output / 'README.md')
    queue = [args.binary.resolve()]
    copied = set()
    search = [args.binary.parent, *args.library_dir]
    index = {}
    for directory in search:
        for path in directory.glob('*.dll'):
            index.setdefault(path.name.lower(), path)
    system = args.system_library_dir or Path(os.environ.get('SystemRoot', 'C:/Windows')) / 'System32'
    while queue:
        binary = queue.pop()
        if args.platform == 'windows':
            dependencies = []
            for dll in pe_imports(binary):
                if dll.lower().startswith(('api-ms-', 'ext-ms-')) or (system / dll).exists():
                    continue
                if dll.lower() not in index:
                    raise FileNotFoundError('Missing DLL: ' + dll)
                dependencies.append(index[dll.lower()])
        else:
            listing = subprocess.check_output(['ldd', str(binary)], text=True)
            if 'not found' in listing:
                raise RuntimeError('Unresolved native library:\n' + listing)
            dependencies = []
            for line in listing.splitlines():
                match = re.search(r'=> (/[^ ]+)', line)
                if not match:
                    continue
                path = Path(match.group(1))
                # Use the host's C ABI, loader and graphics-driver dispatchers.
                if path.name.startswith(('libc.', 'libm.', 'libpthread.', 'libdl.', 'librt.', 'libresolv.', 'libGL.', 'libGLX.', 'libEGL.', 'libOpenGL.', 'libdrm.', 'libgbm.')):
                    continue
                dependencies.append(path)
        for library in dependencies:
            if library.name.lower() in copied:
                continue
            copied.add(library.name.lower())
            shutil.copy2(library, library_dir / library.name)
            queue.append(library.resolve())
    if args.platform == 'windows':
        powershell = shutil.which('powershell.exe') or shutil.which('powershell')
        if powershell is None:
            raise RuntimeError('Windows packaging needs PowerShell (native Windows or WSL) to embed the app icon.')
        def windows_path(path):
            if os.name == 'nt':
                return str(path.resolve())
            return subprocess.check_output(['wslpath', '-w', str(path.resolve())], text=True).strip()
        subprocess.run([powershell, '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', windows_path(root / 'scripts/brand-windows.ps1'),
            '-Executable', windows_path(executable_dir / name),
            '-Icon', windows_path(output / 'Resources/assets/elements.ico'),
            '-Shortcut', windows_path(output / 'Elements Blue Current.lnk')], check=True)
        (output / 'Start Blue Current.cmd').write_bytes(b'@echo off\r\nstart "" "%~dp0bin\\elements-blue-current.exe" %*\r\n')
    else:
        launcher = output / 'Elements Blue Current'
        launcher.write_text('#!/bin/sh\nset -eu\nHERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"\nexport LD_LIBRARY_PATH="$HERE/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"\nexec "$HERE/bin/elements-blue-current" "$@"\n')
        launcher.chmod(0o755)
        shutil.copy2(root / 'scripts/install-desktop.py', output / 'install-desktop.py')
    licenses = output / 'Resources/licenses'
    licenses.mkdir()
    for prefix in args.library_dir:
        for candidate in [prefix.parent/'LICENSE.txt', prefix.parent/'COPYING.txt',prefix.parent.parent/'COPYING.txt']:
            if candidate.exists():
                shutil.copy2(candidate,licenses/(prefix.parent.name+'-'+candidate.name))
        share = prefix.parent / 'share/licenses'
        if share.exists():
            for package in share.iterdir():
                if any(term in package.name.lower() for term in ['sdl2', 'glew', 'gcc-libs', 'libiconv', 'winpthread']):
                    shutil.copytree(package, licenses / package.name, dirs_exist_ok=True)
    print('Packaged', len(copied), 'native libraries in', output)


if __name__ == '__main__':
    main()
