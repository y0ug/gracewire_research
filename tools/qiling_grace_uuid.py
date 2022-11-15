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

@winsdkapi(cc=STDCALL, params={
    'lpRootPathName'           : LPCWSTR,
    'lpVolumeNameBuffer'       : LPWSTR,
    'nVolumeNameSize'          : DWORD,
    'lpVolumeSerialNumber'     : LPDWORD,
    'lpMaximumComponentLength' : LPDWORD,
    'lpFileSystemFlags'        : LPDWORD,
    'lpFileSystemNameBuffer'   : LPWSTR,
    'nFileSystemNameSize'      : DWORD
})
def my_GetVolumeInformationW(ql: Qiling, address: int, params):
    root = params["lpRootPathName"]

    if root == 0:
        raise QlErrorNotImplemented("API not implemented")

    pt_volume_name = params["lpVolumeNameBuffer"]

    if pt_volume_name != 0:
        # TODO implement
        volume_name = (ql.os.profile["VOLUME"]["name"] + "\x00").encode("utf-16le")

        ql.mem.write(pt_volume_name, volume_name)

    lpMaximumComponentLength = params["lpMaximumComponentLength"]
    if lpMaximumComponentLength != 0:
        ql.mem.write_ptr(lpMaximumComponentLength, 255, 2)

    pt_serial_number = params["lpVolumeSerialNumber"]
    if pt_serial_number != 0:
        # write a DWORD instead of a string  
        serial_number = struct.pack('<I', int(ql.os.profile["VOLUME"]["serial_number"]))
        ql.mem.write(pt_serial_number, serial_number)

    pt_system_type = params["lpFileSystemNameBuffer"]
    pt_flag = params["lpFileSystemFlags"]

    if pt_flag != 0:
        # TODO implement
        ql.mem.write_ptr(pt_flag, 0x00020000, 4)

    if pt_system_type != 0:
        system_type = (ql.os.profile["VOLUME"]["type"] + "\x00").encode("utf-16le")
        ql.mem.write(pt_system_type, system_type)

    return 1

def grace_get_uuid(ql, computername, vsn):
    # Set hook on GetVolumeInformationW because Qiling
    # implementation set a string instead of a DWORD in lpVolumeSerialNumber
    # I should push a pull request
    ql.os.set_api("GetVolumeInformationW", my_GetVolumeInformationW, QL_INTERCEPT.CALL)

    # We allocate a buffer and set it as arg0 of the target function
    # IDA detect the calling convention as __thiscall so arg0 is ecx
    ptr = ql.mem.map_anywhere(256, minaddr=0x1000)
    # this string is set the default one set by the malware
    ql.mem.string(ptr, "B597B8EF3F3F4BDE683FEFEF65479B0E")
    ql.arch.regs.write("ecx", ptr)
    #ql.arch.stack_push(ptr)
   
    # We set the sandbox profile to match the target VSN and computername
    ql.os.profile["VOLUME"]["serial_number"] = f'{vsn:d}'
    ql.os.profile["SYSTEM"]["computername"] = computername

    # The unpack version as a bug in the CRT (maybe a bad unpack)
    # we have to stop before the vsnprintf and dump the fmt parameter by hand
    # ql.run(begin=0x4323d0, end=0x4325d7)
    # data = ql.mem.read(ptr, 128)

    ql.run(begin=0x4323d0, end=0x4325c7)

    # We are at the call to vsnprintf we can dump the parameters
    [buffer, buffercount, maxcount, ptr_fmt, arg0, arg1, arg2, arg3, arg4, arg5] = \
        [ ql.arch.stack_pop(), ql.arch.stack_pop(), ql.arch.stack_pop(),
         ql.arch.stack_pop(), ql.arch.stack_pop(), ql.arch.stack_pop(),
         ql.arch.stack_pop(), ql.arch.stack_pop(), ql.arch.stack_pop(),
         ql.arch.stack_pop()]
    
    # We read the format string from the ptr and format it
    fmt = ql.mem.string(ptr_fmt)
    uuid = fmt % ( arg0, arg1, arg2, arg3, arg4, arg5 )
    return uuid

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    parser.add_argument('vsn', type=lambda x: int(x,0))
    parser.add_argument('computername')
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

    uuid = grace_get_uuid(ql, args.computername, args.vsn)
    print(f'{args.computername} ; {args.vsn:#x} ; {uuid}')

