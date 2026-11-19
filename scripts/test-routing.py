#!/usr/bin/env python3
import importlib.util
import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
SPEC=importlib.util.spec_from_file_location('routing_generator',ROOT/'scripts/generate-routing.py')
mod=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mod)

class RoutingTests(unittest.TestCase):
    def test_loopback_pac_dns_direct(self):
        pac=mod.generate_pac('127.0.0.1',1080)
        self.assertIn('SOCKS5 127.0.0.1:1080',pac)
        self.assertNotIn('DIRECT";',pac.split('return "SOCKS5')[-1])
        if not shutil.which("node"):
            self.skipTest("Node.js not installed; PAC JavaScript execution not checked")
        with tempfile.TemporaryDirectory() as tmp:
            p=pathlib.Path(tmp)/'proxy.pac';p.write_text(pac)
            script='''const fs=require('fs'),vm=require('vm');vm.runInThisContext(fs.readFileSync(process.argv[1], 'utf8'));
function dnsDomainIs(h,d){return h.endsWith(d);} function isPlainHostName(h){return !h.includes('.');}
const expected=[['https://example.ru','example.ru','DIRECT'],['https://x.example.su','x.example.su','DIRECT'],['https://xn--e1afmkfd.xn--p1ai','xn--e1afmkfd.xn--p1ai','DIRECT'],['https://example.com','example.com','SOCKS5 127.0.0.1:1080'],['http://192.168.1.3','192.168.1.3','DIRECT']];
for(const [u,h,e] of expected){const actual=FindProxyForURL(u,h);if(actual!==e)throw Error(h+' expected '+e+' got '+actual)}'''
            subprocess.run(['node','-e',script,str(p)],check=True)
    def test_tun_excludes_relay_prevent_recursion(self):
        cfg=mod.generate_tun('1.1.1.1','127.0.0.1',1080)
        self.assertIn('1.1.1.1/32',cfg['inbounds'][0]['route_exclude_address'])
        self.assertTrue(cfg['route']['auto_detect_interface'])
        self.assertEqual(cfg['route']['final'],'rustine')
        self.assertIn({'network':'udp','action':'route','outbound':'block'}, cfg['route']['rules'])
        self.assertEqual(cfg['outbounds'][0]['type'],'socks')
        self.assertEqual(cfg['route']['rule_set'][0]['http_client'],'rules-download')
    def test_no_tun_without_relay_ip(self):
        with tempfile.TemporaryDirectory() as tmp:
            result=subprocess.run(['python3',str(ROOT/'scripts/generate-routing.py'),'--mode','tun','--output',str(pathlib.Path(tmp)/'tun.json')],capture_output=True,text=True)
            self.assertNotEqual(result.returncode,0)
            self.assertIn('--relay-ip is required',result.stderr)
    def test_private_relay_denied(self):
        with self.assertRaises(ValueError):mod.generate_tun('127.0.0.1','127.0.0.1',1080)
    def test_pac_custom_port(self):
        self.assertIn('SOCKS5 127.0.0.1:2080',mod.generate_pac('127.0.0.1',2080))
    def test_tun_json_writes(self):
        with tempfile.TemporaryDirectory() as tmp:
            target=pathlib.Path(tmp)/'tun.json'
            subprocess.run(['python3',str(ROOT/'scripts/generate-routing.py'),'--mode','tun','--relay-ip','1.1.1.1','--output',str(target)],check=True)
            data=json.loads(target.read_text())
            self.assertEqual(data['inbounds'][0]['route_exclude_address'],['1.1.1.1/32'])

if __name__=='__main__':unittest.main()
