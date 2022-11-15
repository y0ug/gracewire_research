#!/usr/bin/env python3
import sys
import os
import struct
import shutil
import argparse
import logging

import pefile

from qiling import *
from qiling.const import QL_VERBOSE

from qiling.os.windows.api import *
from qiling.os.windows.const import *
from qiling.os.windows.fncc import *

from capstone import Cs , CS_ARCH_X86, CS_MODE_32, CS_MODE_64

md = None
logger = logging.getLogger(__name__)


def hook_code(ql, addr, size):
    buf = ql.mem.read(addr, size)
    ins = list(md.disasm(buf, addr))[0]
    ql.log.info(f"0x{ins.address:x}:\t{buf.hex()}\t{ins.mnemonic}\t{ins.op_str}")
    #ql.emu_stop() 

def emulate(ql):
    #ptr = ql.mem.map_anywhere(256, minaddr=0x1000)
    #ql.mem.string(ptr, "hello")
    #ql.arch.stack_push(ptr)
    #ql.arch.regs.write("ecx", ptr)
    #ql.run(begin=0x410000, end=0x41005d)
    return 

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('-v', '--verbose',
                        action='store_true')

    rootfs_path = os.environ.get('QL_ROOTFS', None)
    if rootfs_path == None:
        raise Exception("QL_ROOTFS environment variables need to be set")

    args = parser.parse_args()

    ql_verbose = QL_VERBOSE.DISABLED
    logging.basicConfig(level=logging.ERROR)

    if args.verbose:
        ql_verbose = QL_VERBOSE.DEFAULT
        logger.setLevel(logging.INFO)

    file_toexe = args.filename

    pe = pefile.PE(file_toexe)

    arch = 'x86'
    md = Cs(CS_ARCH_X86, CS_MODE_32)

    if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
        arch = 'x8664'
        md = Cs(CS_ARCH_X86, CS_MODE_64)

    md.detail = True

    # Qiling now require to have the binary in the sandbox path
    # so we are copying it before the execution if is not here 
    rootfs_path = os.path.join(rootfs_path, f'{arch}_windows')
    fp_file_sandbox = os.path.join(rootfs_path, os.path.basename(file_toexe))
    if not os.path.exists(fp_file_sandbox):
        shutil.copy2(file_toexe, fp_file_sandbox)

    ql = Qiling([fp_file_sandbox], 
                rootfs=rootfs_path,
                verbose=ql_verbose)

    if args.verbose:
        ql.hook_code(hook_code)

    emulate(ql)

