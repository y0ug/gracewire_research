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
    for ea in range(start_ea, end_ea):
        patch_byte(ea, 0x90)

def read_n_ins(ea, n):
    vals = []
    for i in range(n): 
        insn = idaapi.insn_t()
        idaapi.decode_insn(insn, ea)
        dis = idc.GetDisasm(ea)
        insn_mnem = idc.print_insn_mnem(ea)
        vals.append([ea, insn, dis, insn_mnem])
        ea = idc.next_head(ea)
        if not ea: break

    return vals

def color(start, end, color_code):
    ea = start
    while ea <= end:
        idc.set_color(ea, idc.CIC_ITEM, color_code)
        ea = idc.next_head(ea)

def patch(start, end, color_code):
    patch_nops(start, end)
    color(start, end, color_code)

def remove_junk_per_func(ea):
    f = ida_funcs.get_func(ea)
    if f == None:
        print(f'[-] address given - {hex(ea)} does not belong to a function')
        return False

    removal_list = [] # contains all removed code ranges

    print(f'[+] attempting to remove junk code for function {ida_funcs.get_func_name(ea)}') 

    # mov reg, address
    # xor/sub/and/imul, reg, val
    # mov address, reg 
    ea = f.start_ea

    while ea < f.end_ea:
        vals = read_n_ins(ea, 6)
        #print(vals)
        if len(vals) != 6: break 
        #print(f"try {vals[0][0]:x}")

        if vals[0][3].startswith("mov") and vals[1][3].startswith("mov") and \
                vals[2][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
                vals[3][3] == "mov" and \
                idc.get_operand_type(vals[3][0], 0) == 0x2 and \
                idc.get_operand_type(vals[0][0], 0) == 0x1:
            print(f"case1 {vals[0][0]:x}")
            ea = idc.next_head(vals[3][0])
            patch(vals[0][0], ea, 0x33FF3F)
        elif vals[0][3].startswith("mov") and vals[1][3].startswith("mov") and \
                vals[2][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
                vals[3][3] == "mov" and vals[4][3] == "mov" and \
                idc.get_operand_type(vals[0][0], 0) == 0x1:
            print(f"case2 {vals[0][0]:x}")
            ea = idc.next_head(vals[4][0])
            #patch_nops(vals[0][0], ea)
            patch(vals[0][0], ea, 0xDAFF33)

        #elif vals[0][3].startswith("mov") and \
        #        vals[1][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
        #        vals[2][3] == "mov" and vals[3][3] == "mov":
        #    print(f"win2 {vals[0][0]:x}")
        #    patch_nops(vals[0][0], idc.next_head(vals[3][0]))
        #    ea = idc.next_head(vals[3][0])
        elif vals[0][3].startswith("mov") and \
                vals[1][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
                vals[2][3] == "mov" and \
                vals[3][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
                vals[4][3] == "mov" and \
                idc.get_operand_type(vals[0][0], 0) == 0x1:
            print(f"case3 {vals[0][0]:x}")
            ea = idc.next_head(vals[4][0])
            patch(vals[0][0], ea, 0x33FFFF)

        elif vals[0][3].startswith("mov") and \
                (idc.get_operand_value(vals[0][0], 0) == 0x0 or idc.get_operand_value(vals[0][0], 0) == 0x1) and \
                vals[1][3] in ['xor', 'add', 'sub', 'and', 'imul', 'or'] and \
                vals[2][3] == "mov" and \
                idc.get_operand_type(vals[0][0], 0) == 0x1 and idc.get_operand_type(vals[2][0], 0) == 0x2:
            print(f"case4 {vals[0][0]:x}")
            ea = idc.next_head(vals[2][0])
            patch(vals[0][0], ea, 0x3386FF)

        elif vals[0][3].startswith("imul") and idc.get_operand_type(vals[0][0], 2) == 0x5 and \
                vals[1][3] == "mov":
            print(f"case5 {vals[0][0]:x}")
            ea = idc.next_head(vals[1][0])
            patch(vals[0][0], ea, 0x133760)
        else:
            color(ea, ea, 0xFF33B5)
            ea = idc.next_head(ea)

    ida_bytes.del_items(f.start_ea, 0, f.end_ea - f.start_ea)
    idc.create_insn(f.start_ea)
    ida_funcs.add_func(f.start_ea, f.end_ea)

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
for ea in idautils.Functions():
    func = idaapi.get_func(ea)
    print(f"processing {idc.get_func_name(func.start_ea)}")
    remove_junk_per_func(func.start_ea)
