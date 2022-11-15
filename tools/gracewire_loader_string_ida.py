import idaapi, idc, ida_hexrays

mKey = idaapi.get_bytes(0x18008AB90, 0x64)

def ida_set_hexrays_comment(adr, val):
    cfunc = idaapi.decompile(adr)
    eamap = cfunc.get_eamap()
    decompObjAddr = eamap[adr][0].ea

    tl = idaapi.treeloc_t()
    for itp in range(idaapi.ITP_SEMI, idaapi.ITP_COLON):
        tl.ea = decompObjAddr
        tl.itp = itp
        cfunc.set_user_cmt(tl, val)
        unused = cfunc.__str__()
        if not cfunc.has_orphan_cmts():
            commentSet = True
            cfunc.save_user_cmts()
            break
        cfunc.del_orphan_cmts()

def ida_set_comment(adr, val):
    idc.set_cmt(adr, val, 0)
    ida_set_hexrays_comment(adr, val)

def decode(val, n, key, isUnicode):
    o = []
    for i in range(0, n):
        j = i if isUnicode == 2 else i*1
        x = val[j] ^ mKey[i % len(mKey)] ^ key
        o.append(x)
    return bytes(o)


fn = idc.get_name_ea_simple('DecodeString')
for xref in CodeRefsTo(fn, 1):
    args = idaapi.get_arg_addrs(xref)
    if args:
        lpBuf = idc.get_operand_value(args[0], 1)
        dwLen = idc.get_operand_value(args[1], 1)
        bKey = idc.get_operand_value(args[2], 1)
        bIsUnicode = idc.get_operand_value(args[3], 1)
        val = idaapi.get_bytes(lpBuf, dwLen)

        #try:
        val = decode(val, dwLen, bKey, bIsUnicode)
        #val_ = val.decode().replace('\\', '_').replace('%','_')
        #idc.set_name(lpBuf, f'lp{val_}')
        print(hex(xref), val)
        ida_set_comment(xref, repr(val))
        #except Exception as ex:
        #    print(ex)
        #    pass
