#!/usr/bin/env python3
"""Derive platform icon containers from the unchanged, transparent master logo."""
from pathlib import Path
from PIL import Image

assets = Path(__file__).resolve().parents[1] / 'assets'
with Image.open(assets / 'elements-logo.png') as source:
    logo = source.convert('RGBA')
    logo.save(assets / 'elements.ico', sizes=[(n, n) for n in [16, 24, 32, 48, 64, 128, 256]])
    logo.save(assets / 'elements.icns')
print('Generated Windows and macOS icons from elements-logo.png')
