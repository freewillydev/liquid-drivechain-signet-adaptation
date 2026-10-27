"""Reject mixed frontend distributions and links outside a release input."""
from pathlib import Path


def validate_inputs(wallet, node, platform):
    wallet, node = Path(wallet).resolve(), Path(node).resolve()
    suffix = '.exe' if platform == 'windows' else ''
    wallet_entry = ('Elements Blue Current.app/Contents/MacOS/elements-blue-current'
                    if platform == 'macos' else 'bin/elements-blue-current' + suffix)
    for root, entries in [(wallet, [wallet_entry]),
                          (node, ['bin/elementsd' + suffix, 'bin/elements-cli' + suffix])]:
        for name in entries:
            if not (root / name).is_file():
                raise ValueError('Missing bundled executable: ' + name)
        for path in root.rglob('*'):
            if path.is_symlink() and not path.resolve().is_relative_to(root):
                raise ValueError('Bundle link escapes its input: ' + str(path))
            if path.suffix == '.app' and path.name != 'Elements Blue Current.app':
                raise ValueError('Only the Blue Current app may be bundled')
            if path.is_file():
                name = path.name.lower()
                if any(term in name for term in ['elements-qt', 'elements-gui', 'liquid-symphony', 'pokedex']):
                    raise ValueError('Legacy frontend in release: ' + name)
                if path.parent.name in ['bin', 'MacOS']:
                    relative = path.relative_to(root).as_posix()
                    library = name.endswith(('.dll', '.dylib')) or '.so' in name
                    if not library and relative not in entries:
                        raise ValueError('Unexpected executable in bundle: ' + relative)
