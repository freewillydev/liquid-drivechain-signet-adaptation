#!/usr/bin/env python3
"""Bundle prebuilt Elements executables and every non-system Mach-O dependency.

No consensus code is built or changed. Input binaries must be from one qualified
node build. Output is suitable for node/ in a combined Bitwindow release.
"""
import argparse,hashlib,json,os,re,shutil,subprocess
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--daemon',required=True,type=Path);p.add_argument('--cli',required=True,type=Path);p.add_argument('--output',required=True,type=Path)
a=p.parse_args();out=a.output.resolve()
if out.exists():raise SystemExit('Output must be a new directory')
(out/'bin').mkdir(parents=True);(out/'lib').mkdir()
def command(*args):return subprocess.check_output([str(x) for x in args],text=True)
def dependencies(path):return [s.strip().split(' (')[0] for s in command('otool','-L',path).splitlines()[1:]]
def rpaths(path):return re.findall(r'cmd LC_RPATH\s+cmdsize \d+\s+path (.*?) \(offset',command('otool','-l',path))
def digest(path):return hashlib.file_digest(path.open('rb'),'sha256').hexdigest()
def system(path):return path.startswith(('/usr/lib/','/System/Library/'))
seen={};records={}
def expand(path,loader,executable):return Path(path.replace('@loader_path',str(loader.parent)).replace('@executable_path',str(executable.parent)))
def copy(source,target,inherited,executable):
 source=source.resolve()
 key=str(source)
 if key in seen:return seen[key]
 if target.exists() and digest(target)!=digest(source):raise RuntimeError('Conflicting dependency basename '+str(target))
 before=digest(source);shutil.copy2(source,target)
 if digest(source)!=before or digest(target)!=before:raise RuntimeError('Input changed while packaging '+str(source))
 seen[key]=target;records[str(target.relative_to(out))]={'source_sha256':before}
 paths=[expand(r,source,executable) for r in rpaths(source)]+inherited
 for dep in dependencies(source):
  if system(dep) or dep==str(source) or dep=='@rpath/'+source.name:continue
  if dep.startswith('@rpath/'):
   candidates=[base/dep[len('@rpath/'):] for base in paths]
  else:candidates=[expand(dep,source,executable)]
  found=next((x for x in candidates if x.is_file()),None)
  if found is None:raise RuntimeError('Missing dependency '+dep+' of '+str(source))
  child=copy(found,out/'lib'/found.name,paths,executable)
  relative=os.path.relpath(child,target.parent)
  subprocess.run(['install_name_tool','-change',dep,'@loader_path/'+relative,str(target)],check=True,capture_output=True)
 # Remove all inherited build-machine search paths, including GHC/Cabal stores.
 for rpath in rpaths(target):subprocess.run(['install_name_tool','-delete_rpath',rpath,str(target)],check=True,capture_output=True)
 if target.suffix=='.dylib':subprocess.run(['install_name_tool','-id','@rpath/'+target.name,str(target)],check=True,capture_output=True)
 subprocess.run(['codesign','--force','--sign','-',str(target)],check=True,capture_output=True)
 return target
for source,name in [(a.daemon,'elementsd'),(a.cli,'elements-cli')]:copy(source,out/'bin'/name,[],source.resolve())
for target in [*(out/'lib').glob('*'),*(out/'bin').glob('*')]:
 for dep in dependencies(target):
  if not system(dep) and not dep.startswith('@loader_path/') and dep!='@rpath/'+target.name:raise RuntimeError('Unbundled dependency '+dep)
 records[str(target.relative_to(out))]['sha256']=digest(target)
(out/'bundle-checksums.json').write_text(json.dumps(records,indent=2)+'\n')
print(json.dumps({'files':len(records),'output':str(out)}))
