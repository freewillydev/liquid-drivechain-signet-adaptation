#!/usr/bin/env python3
"""Exercise owned/attached node lifecycle in isolated, unfunded regtest folders."""
import argparse,json,socket,subprocess,tempfile,time
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('--wallet',required=True,type=Path);p.add_argument('--daemon',required=True,type=Path);p.add_argument('--cli',required=True,type=Path);p.add_argument('--work-parent',required=True,type=Path)
a=p.parse_args();root=Path(tempfile.mkdtemp(prefix='node-profile-',dir=a.work_parent));data=root/'node data';data.mkdir()
with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
flags=['-chain=elementsregtest','-datadir='+str(data),'-rpcport='+str(port)]
nodeargs=['-listen=0','-connect=0','-initialfreecoins=2100000000000000','-validatepegin=0','-anyonecanspendaremine=1','-con_connect_genesis_outputs=1','-con_blocksubsidy=0']
def rpc(*args):return subprocess.run([str(a.cli),*flags,*args],text=True,capture_output=True,check=True,timeout=15).stdout.strip()
def start():
 log=(root/'bootstrap.log').open('a')
 node=subprocess.Popen([str(a.daemon),*flags,*nodeargs],stdout=log,stderr=log);log.close()
 for _ in range(150):
  if node.poll() is not None:raise RuntimeError('test daemon exited; '+str(root))
  try:rpc('getblockchaininfo');return node
  except subprocess.SubprocessError:time.sleep(.1)
 raise RuntimeError('node never became ready')
def stop(node):
 try:rpc('stop')
 except subprocess.SubprocessError:node.terminate()
 node.wait(timeout=20)
def check(profile,success=True):
 path=root/'profile.json';path.write_text(json.dumps(profile))
 result=subprocess.run([str(a.wallet),'--check-node-profile',str(path)],text=True,capture_output=True,timeout=50)
 with (root/'wallet-checks.log').open('a') as f:f.write(result.stdout+result.stderr)
 assert (result.returncode==0)==success,(result.stdout,result.stderr)
node=start()
try:
 info=json.loads(rpc('getsidechaininfo'))
 profile={'schema':'elements-blue-current-node-v1','name':'Isolated functional qualification','cli':str(a.cli),'daemon':str(a.daemon),'chain':'elementsregtest','datadir':str(data),'rpcport':port,'wallet':'ui-test','startNode':True,'nodeArgs':nodeargs,'identity':{'name':'Isolated functional qualification','target':'functional-regtest','ready':True,'genesis':rpc('getblockhash','0').strip('"'),'asset':info['pegged_asset'],'parentGenesis':info['parent_blockhash'],'parentForkHeight':None}}
 check(profile);assert node.poll() is None,'attached node was stopped'
 print('PASS: attaches to existing node and leaves it running')
 wrong=json.loads(json.dumps(profile));wrong['identity']['genesis']='1'*64
 check(wrong,False);assert node.poll() is None
 print('PASS: wrong chain is rejected without stopping attached node')
finally:stop(node)
check(profile)
try:rpc('getblockchaininfo');raise AssertionError('owned node still running')
except subprocess.CalledProcessError:pass
print('PASS: starts an owned node and stops it gracefully on exit')
pending=json.loads(json.dumps(profile));pending['identity']['ready']=False
check(pending,False)
try:rpc('getblockchaininfo');raise AssertionError('pending profile started a node')
except subprocess.CalledProcessError:pass
print('PASS: unfinished production profile never starts a node')
print('Evidence: '+str(root))
