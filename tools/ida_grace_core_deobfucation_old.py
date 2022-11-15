import binascii
import hashlib


import idaapi
import idautils
import ida_allins
import idc
from collections import deque

def remove_junk_code(start_ea, end_ea):
    pass

junk_start = 0x18009F000
junk_end = 0x1800A19DA 

def patch_nops(start_ea, end_ea):
    """patches nop instructions (0x90) on all bytes. not including last byte
    (WASN'T USED IN PLUGIN. KEPT FOR REFERENCING)
    """
    for ea in range(start_ea, end_ea):
        patch_byte(ea, 0x90)

def read_n_ins(ea, n):
    vals = []
    for i in range(n): 
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        dis = idc.GetDisasm(ea)
        vals.append([ea, insn, dis])
        ea = idc.next_head(ea)

    return vals

def remove_junk_per_func(ea):
    f = ida_funcs.get_func(ea)
    if f == None:
        print(f'[-] address given - {hex(ea)} does not belong to a function')
        return False

    removal_list = [] # contains all removed code ranges

    print(f'[+] attempting to remove junk code for function {ida_funcs.get_func_name(ea)}') 
    
    # mov reg, address
    # xor/sub/and/imul, reg, val
    # 
    for ea in Heads(f.start_ea, f.end_ea):
        insn = idaapi.insn_t()
        length = idaapi.decode_insn(insn, ea)
        if insn.itype == ida_allins.NN_movzx or insn.itype == ida_allins.NN_mov:
            if insn.ops[1].type == ida_ua.o_mem:
                adr = idc.get_operand_value(ea, 1) # we've detect the mov

                print(f"Data is moved at addr {junk_start:x} <= {adr:x}")
                dis = idc.GetDisasm(ea)
                print(dis)

                ea_1 = idc.next_head(ea)
                print(idc.GetDisasm(ea_1))
                length = idaapi.decode_insn(insn, ea_1)
                if insn.itype == ida_allins.NN_xor or \
                        insn.itype == ida_allins.NN_add or \
                        insn.itype == ida_allins.NN_sub or \
                        insn.itype == ida_allins.NN_xor or \
                        insn.itype == ida_allins.NN_and or \
                        insn.itype == ida_allins.NN_neg:
                

                    ea_2 = idc.next_head(ea_1)
                    print(idc.GetDisasm(ea_2))
                    length = idaapi.decode_insn(insn, ea_2)
                    if insn.itype == ida_allins.NN_movzx or insn.itype == ida_allins.NN_mov:
                        if insn.ops[0].type == ida_ua.o_mem:
                            print("winner")

                            ea_3 = idc.next_head(ea_2)

                            patch_nops(ea, ea_3)
                #adr = insn.ops[1].value


#------------------------------------------------------------------------------
# IDA Plugin
#------------------------------------------------------------------------------

VERSION = "v1.0"
AUTHORS = ['Hugo Caron']

def PLUGIN_ENTRY():
    """
    Required plugin entry point for IDAPython Plugins.
    """
    return deobf_junk_t()

class deobf_junk_t(idaapi.plugin_t):

    flags = idaapi.PLUGIN_FIX
    comment = ""
    help = ""
    wanted_name = "Remove GraceWire obfuscation"
    wanted_hotkey = "Alt-F3"

    def __init__(self):
        pass

    def init(self):
        idaapi.msg('Init plugin')
        return PLUGIN_OK

    def run(self, arg):
        """
        This is called by IDA when this file is loaded as a script.
        """
        ea = idc.here()
        idaapi.msg(f'plugin run {ea:x}')
        remove_junk_per_func(ea)

    def term(self):
        pass



ea = idc.here()
idaapi.msg(f'plugin run {ea:x}')
remove_junk_per_func(ea)
