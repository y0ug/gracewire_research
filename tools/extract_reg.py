import sys
import zlib
import io
import re
from configparser import ConfigParser
import binascii
import argparse
import struct
import socket
from datetime import datetime

def read_reg(filename):
    out = []
    with io.open(filename, encoding='utf-16') as f:
        data = f.read()
    data = re.sub(r'^[^\[]*\n', '', data, flags=re.S)
    cfg = ConfigParser(strict=False)
    # dirty hack for "disabling" case-insensitive keys in "configparser"
    cfg.optionxform=str
    cfg.read_string(data)
    for s in cfg.sections():
        for key in cfg[s]:
            val = cfg[s][key]
            if val.startswith('hex:'):
                val = val[4:].replace('\\\n','').replace(',','')
                val = binascii.unhexlify(val)
                out.append([ s + '\\' + key.strip('"'), val])
    return out

def write_reg(key, vn, vd):
    header = "Windows Registry Editor Version 5.00\n\n"
    l1 = f'[{key}]\n'
    vd_ = ','.join([f'{x:02x}' for x in vd])
    l2 = f'"{vn}"=hex:{vd_}\n'
    return header + l1 + l2

if __name__ == "__main__":
    payload = read_reg(sys.argv[1])
    open('out.bin', 'wb').write(payload[0][1])
