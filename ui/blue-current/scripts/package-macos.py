#!/usr/bin/env python3
"""Package a built Haskell executable with fonts and native graphics libraries."""
import argparse, os, plistlib, re, shutil, subprocess
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('binary',type=Path)
p.add_argument('--output',type=Path,default=Path('build/Elements Blue Current.app'))
p.add_argument('--identity',default='-')
p.add_argument('--bundle-id',default='org.elements.bluecurrent.preview')
p.add_argument('--name',default='Elements Blue Current')
a=p.parse_args(); root=Path(__file__).resolve().parents[1];app=a.output.resolve()
mac=app/'Contents/MacOS'; resources=app/'Contents/Resources'; libs=app/'Contents/Frameworks'
for folder in [mac,resources,libs]:folder.mkdir(parents=True,exist_ok=True)
binary=mac/'elements-blue-current';shutil.copyfile(a.binary,str(binary)+'.next');os.chmod(str(binary)+'.next',0o755)
subprocess.run(['strip','-x',str(binary)+'.next'],check=True);os.replace(str(binary)+'.next',binary)
shutil.copytree(root/'assets',resources/'assets',dirs_exist_ok=True)
shutil.copyfile(root/'assets/elements.icns',resources/'elements.icns')
shutil.copyfile(root/'README.md',resources/'README.md')
licenses=resources/'licenses';licenses.mkdir(exist_ok=True)
dependencies=[line.strip().split(' (')[0] for line in subprocess.check_output(['otool','-L',str(binary)],text=True).splitlines()[1:]]
for formula,name in [('glew','libGLEW.2.3.dylib'),('sdl2','libSDL2-2.0.0.dylib')]:
 original=Path(next(path for path in dependencies if path.endswith('/'+name)))
 prefix=original.resolve().parent.parent;target=libs/name;staging=libs/(name+'.next')
 shutil.copyfile(original,staging);os.chmod(staging,0o755)
 subprocess.run(['install_name_tool','-id','@executable_path/../Frameworks/'+name,str(staging)],check=True)
 os.replace(staging,target)
 subprocess.run(['install_name_tool','-change',str(original),'@executable_path/../Frameworks/'+name,str(binary)],check=True)
 license_file=next((prefix/name for name in ['LICENSE','LICENSE.txt','COPYING.txt'] if (prefix/name).exists()),None)
 if license_file is None:raise RuntimeError('Missing graphics library license: '+str(prefix))
 shutil.copyfile(license_file,licenses/(formula+'.txt'))
versions=[]
for target in [binary,*libs.glob('*.dylib')]:
 build=subprocess.check_output(['xcrun','vtool','-show-build',str(target)],text=True)
 versions.extend(re.findall(r'\bminos\s+([0-9.]+)',build))
minimum=max(versions,key=lambda version:tuple(map(int,version.split('.'))))
info={'CFBundleExecutable':'elements-blue-current','CFBundleIdentifier':'org.elements.bluecurrent.preview','CFBundleName':'Elements Blue Current','CFBundlePackageType':'APPL','CFBundleShortVersionString':'0.1.0','CFBundleVersion':'2','NSRemovableVolumesUsageDescription':'Connect to your Elements node and wallet files on this drive.','NSHighResolutionCapable':True,'LSMinimumSystemVersion':minimum}
info['CFBundleIconFile']='elements.icns'
info['CFBundleIdentifier']=a.bundle_id
info['CFBundleName']=a.name
info['CFBundleVersion']='3'
with (app/'Contents/Info.plist').open('wb') as f:plistlib.dump(info,f)
subprocess.run(['xattr','-cr',str(app)],check=True)
subprocess.run(['codesign','--force','--deep','--sign',a.identity,str(app)],check=True)
subprocess.run(['codesign','--verify','--deep','--strict',str(app)],check=True)
# Fail packaging if any build-machine path remains in the dependency list.
for target in [binary,*libs.glob('*.dylib')]:
 lines=subprocess.check_output(['otool','-L',str(target)],text=True).splitlines()[1:]
 for line in lines:
  dependency=line.strip().split(' (')[0]
  if not dependency.startswith(('/usr/lib/','/System/Library/','@')):raise RuntimeError('Unbundled dependency: '+dependency)
print(app)
