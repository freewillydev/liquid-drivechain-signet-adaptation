#!/usr/bin/env python3
"""Install an optional Linux application-menu entry at the bundle's current path."""
import os
from pathlib import Path

root = Path(__file__).resolve().parent
data = Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local/share'))
applications = data / 'applications'
applications.mkdir(parents=True, exist_ok=True)

def quoted(value):
    return '"' + str(value).replace('\\', '\\\\').replace('"', '\\"').replace('`', '\\`').replace('$', '\\$') + '"'

entry = applications / 'org.elements.bluecurrent.desktop'
entry.write_text('[Desktop Entry]\nType=Application\nName=Elements Blue Current\n'
    'Comment=Elements wallet\nExec=' + quoted(root / 'Elements Blue Current') + '\n'
    'Icon=' + str(root / 'Resources/assets/elements-logo.png') + '\n'
    'Terminal=false\nCategories=Finance;\nStartupWMClass=elements-blue-current\n')
print(entry)
