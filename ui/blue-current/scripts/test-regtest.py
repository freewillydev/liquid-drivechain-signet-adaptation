#!/usr/bin/env python3
"""Run the integration suite against a fresh, isolated local Elements node."""
import argparse, os, socket, subprocess, tempfile, time
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('--elements-bin',required=True,type=Path)
p.add_argument('--daemon-name',default='elementsd');p.add_argument('--cli-name',default='elements-cli');p.add_argument('--work-parent',required=True,type=Path);p.add_argument('test_command',nargs=argparse.REMAINDER)
a=p.parse_args();suffix='.exe' if os.name=='nt' else ''
a.work_parent.mkdir(parents=True,exist_ok=True)
with tempfile.TemporaryDirectory(prefix='blue-current-regtest-',dir=a.work_parent) as directory:
 root=Path(directory);datadir=root/'data';datadir.mkdir()
 with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=str(sock.getsockname()[1])
 binary=a.elements_bin.resolve();cli=[str(binary/(a.cli_name+suffix)),'-chain=elementsregtest','-datadir='+str(datadir),'-rpcport='+port]
 def rpc(*args):return subprocess.run(cli+list(args),capture_output=True,text=True,timeout=15,check=True).stdout
 with (root/'node.log').open('w') as log:
  node=subprocess.Popen([str(binary/(a.daemon_name+suffix)),'-chain=elementsregtest','-datadir='+str(datadir),'-rpcport='+port,'-listen=0','-connect=0','-initialfreecoins=2100000000000000','-validatepegin=0','-anyonecanspendaremine=1','-con_connect_genesis_outputs=1','-con_blocksubsidy=0'],stdout=log,stderr=log)
  try:
   for attempt in range(100):
    if node.poll() is not None:raise RuntimeError('Isolated node exited; see '+str(root/'node.log'))
    try:rpc('getblockchaininfo');break
    except (subprocess.SubprocessError,OSError):time.sleep(.1)
   else:raise RuntimeError('Isolated node did not become ready')
   rpc('createwallet','ui-test');rpc('-rpcwallet=ui-test','rescanblockchain')
   env=dict(os.environ,BLUE_CURRENT_TEST_ROOT=str(root),BLUE_CURRENT_TEST_CLI=cli[0],BLUE_CURRENT_TEST_DATADIR=str(datadir),BLUE_CURRENT_TEST_PORT=port)
   command=a.test_command or ['cabal','test','live-wallet','--test-show-details=direct']
   if command[0]=='--':command=command[1:]
   subprocess.run(command,env=env,check=True)
  finally:
   try:rpc('stop')
   except (subprocess.SubprocessError,OSError):node.terminate()
   try:node.wait(timeout=15)
   except subprocess.TimeoutExpired:node.kill();node.wait()
