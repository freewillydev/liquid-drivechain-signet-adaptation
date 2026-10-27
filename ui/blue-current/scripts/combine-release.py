#!/usr/bin/env python3
"""Create the exact native-wallet bundle Bitwindow installs, plus pinned metadata.

Consumes already qualified portable inputs; does not publish a release or select
consensus parameters. Missing production identity/URL leaves ready=false.
"""
import argparse,hashlib,json,os,plistlib,shutil,stat,subprocess,tarfile,zipfile
from pathlib import Path
from bundle_policy import validate_inputs
p=argparse.ArgumentParser();p.add_argument('--wallet-dir',required=True,type=Path);p.add_argument('--node-dir',required=True,type=Path);p.add_argument('--identity',required=True,type=Path);p.add_argument('--platform',required=True,choices=['macos-arm64','macos-x86_64','windows-x86_64','linux-x86_64']);p.add_argument('--version',required=True);p.add_argument('--base-url');p.add_argument('--output',required=True,type=Path)
a=p.parse_args();out=a.output.resolve()
if out.exists():raise SystemExit('Choose a new output directory')
if not a.version or Path(a.version).name!=a.version or a.version in ['.','..']:raise SystemExit('Invalid release version')
identity=json.loads(a.identity.read_text())
if identity['target']!='btc-ecx-mainnet' or identity['parentForkHeight']!=973728 or identity['parentGenesis']!='000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f':raise SystemExit('Wrong BTC to ECX deployment target')
if identity.get('ready'):
 for key in ['genesis','asset']:
  value=identity.get(key,'')
  if len(value)!=64 or any(c not in '0123456789abcdef' for c in value) or set(value)=={'0'}:raise SystemExit('Missing production '+key)
 if identity['genesis'] in ['672af009bd90bfc6527a5a9dda4c83aba0048c15cff3697d07e89a7f96fa5bcd','a7754ce0debc40baddbd8c47e79d19209685f22c63edaaf8b69cf54116374d7f']:raise SystemExit('Historical child cannot become production')
 if not identity.get('chain_directory') or '/' in identity['chain_directory'] or '\\' in identity['chain_directory']:raise SystemExit('Missing production chain directory')
if a.base_url and not a.base_url.startswith('https://'):raise SystemExit('Release URL must use HTTPS')
platform=a.platform.split('-')[0];suffix='.exe' if platform=='windows' else ''
validate_inputs(a.wallet_dir, a.node_dir, platform)
root=out/'Elements Blue Current';root.mkdir(parents=True)
shutil.copytree(a.wallet_dir,root/'wallet',symlinks=True);shutil.copytree(a.node_dir,root/'node',symlinks=True)
if platform=='macos':
 wallet='wallet/Elements Blue Current.app/Contents/MacOS/elements-blue-current'
 profile=root/'wallet/Elements Blue Current.app/Contents/Resources/node-profile.json'
elif platform=='linux':
 wallet='wallet/Elements Blue Current'
 profile=root/'wallet/Resources/node-profile.json'
else:
 wallet='wallet/bin/elements-blue-current'
 profile=root/'wallet/Resources/node-profile.json'
daemon='node/bin/elementsd';cli='node/bin/elements-cli'
for entry in [wallet,daemon,cli]:
 path=root/(entry+suffix if platform=='windows' else entry)
 if not path.is_file():raise SystemExit('Missing bundled executable: '+str(path))
# A direct launch explains unfinished deployment rather than silently opening Demo or Alpha.
profile.parent.mkdir(parents=True,exist_ok=True)
profile.write_text(json.dumps({'schema':'elements-blue-current-node-v1','name':identity['name'],'cli':os.path.relpath(root/(cli+suffix),profile.parent),'daemon':os.path.relpath(root/(daemon+suffix),profile.parent),'chain':'elements','wallet':'bitwindow','startNode':False,'nodeArgs':[],'identity':dict(identity,ready=False,target=('bitwindow-setup' if identity.get('ready') else identity['target']))},indent=2)+'\n')
if platform=='macos':
 plist=root/'wallet/Elements Blue Current.app/Contents/Info.plist'
 info=plistlib.loads(plist.read_bytes());info['CFBundleIdentifier']='org.elements.bluecurrent.integrated';plist.write_bytes(plistlib.dumps(info))
 subprocess.run(['codesign','--force','--deep','--sign','-',str(root/'wallet/Elements Blue Current.app')],check=True)
(root/'network.json').write_text(json.dumps(identity,indent=2)+'\n')
(root/'README.txt').write_text('Elements Blue Current wallet and node\n\nTarget: Elements sidechain anchored to the BTC to ECX fork at Bitcoin block 973,728.\nProduction activation requires a reviewed child genesis/native asset and matching qualified node release. This package does not convert the retired Alpha/Betanet chain into production.\n\nBitwindow owns the node process and passes a private connection profile to the wallet. Existing chain data is preserved. The Elements wallet is independent of the Bitwindow starter wallet: use Blue Current Backup & recovery to back it up.\n')
def sha(path):
 with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
checksums={str(f.relative_to(root)):sha(f) for f in root.rglob('*') if f.is_file() and not f.is_symlink()}
(root/'checksums.json').write_text(json.dumps(checksums,indent=2)+'\n')
archive=out/(f'Elements-Blue-Current-{a.version}-{a.platform}'+('.tar.gz' if platform=='linux' else '.zip'))
if platform=='linux':
 with tarfile.open(archive,'w:gz') as tar:tar.add(root,arcname=root.name)
else:
 with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
  for path in sorted(root.rglob('*')):
   if path.is_symlink():
    info=zipfile.ZipInfo(str(path.relative_to(out)));info.create_system=3;info.external_attr=(stat.S_IFLNK|0o777)<<16;z.writestr(info,os.readlink(path))
   elif path.is_file():z.write(path,path.relative_to(out))
metadata={'ready':bool(identity.get('ready') and a.base_url),'version':a.version,'binary':{platform:wallet},'daemon':{platform:daemon},'cli':{platform:cli},'download_urls':({'default':a.base_url.rstrip('/')+'/'} if a.base_url else {}),'files':{a.platform:archive.name},'extract_subfolder':{platform:root.name},'artifact_pins':{a.platform:{'archive_sha256':sha(archive),'executable_sha256':sha(root/(wallet+suffix if platform=='windows' else wallet))}},'daemon_sha256':{a.platform:sha(root/(daemon+suffix))},'cli_sha256':{a.platform:sha(root/(cli+suffix))},'identity':identity,'node_args':[]}
metadata['ui']='blue-current'
(out/'native-wallet.json').write_text(json.dumps(metadata,indent=2)+'\n')
print(json.dumps({'archive':str(archive),'ready':metadata['ready'],'metadata':str(out/'native-wallet.json')}))
