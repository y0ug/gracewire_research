from idc import *
from idaapi import *
from idautils import *
from ida_enum import *

def apply_enum_rcx(function_ea, target_enum_name, before_limit=0x30):

	enum_id = get_enum(target_enum_name)

	for xref in XrefsTo(function_ea, 0):
		current_ea = xref.frm

		while current_ea != BADADDR:
			current_ea = prev_head(current_ea, xref.frm - before_limit)
			
			# mov     ecx, 0x40 
			if get_operand_type(current_ea, 0) == 0x1 and get_operand_value(current_ea, 0) == 0x1 and get_operand_type(current_ea, 1) == 0x5:
				eop = get_operand_value(current_ea, 1)
				eid = get_enum_member(enum_id, eop, 0, 0)
				e_str = idc.get_enum_member_name(eid)
				print(f"resolv {current_ea:x}h {eop:x}h {e_str:s}")
				op_enum(current_ea, 1, enum_id, 0)
				break


fn = idc.get_name_ea_simple('resolv')
apply_enum_rcx(fn, "RESOLV_IDS")
