import sys
import struct
import argparse

def get_uuid(key, cn, vsn):
    val1 = key ^ vsn
    val2 = (key ^ vsn) >> 8

    val = b''

    val += struct.pack('<I', val1)
    val += struct.pack('<I', val1)

    val += ((key ^ vsn ^ cn[0] ^ vsn) & 0xff).to_bytes(1, byteorder='big')
    val += ((vsn ^ val2 ^ cn[1]) & 0xff).to_bytes(1, byteorder='big')

    for i in range(2, 8):
        j = i % len(cn)
        val += ((vsn ^ val[i] ^ cn[j%len(cn)]) & 0xff).to_bytes(1, byteorder='big')

    return val

def p_uuid(key, cn, vsn, fmt='guuid'):
    val = get_uuid(key, cn, vsn)
    out = []
    if not isinstance(fmt, list):
        fmt = [fmt,]

    for f in fmt:
        if f == "hex":
            val_ = val.hex()
        elif f == "key":
            val_ = "%.08X%s%.04X%s%.04X%s%.04X%s%.02X%.02X%.02X%.02X%.02X%.02X" % (
                struct.unpack('<I', val[0:4])[0], '',
                struct.unpack('<H', val[4:6])[0], '',
                struct.unpack('<H', val[6:8])[0], '',
                struct.unpack('<H', val[8:10])[0], '',
                val[10], val[11], val[12], val[13], val[14], val[15])
            val_ = val_[0:0x10].upper()
        elif f == "mutex":
            val_ = 'm' + val[1:].hex().upper()
        elif f == "global":
            val_ = 'Global\\' + val.hex()
        elif f == "local":
            val_ = "Local\\%.08X%s%.04X%s%.04X%s%.04X%s%.02X%.02X%.02X%.02X%.02X%.02X" % (
                struct.unpack('<I', val[0:4])[0], '-',
                struct.unpack('<H', val[4:6])[0], '-',
                struct.unpack('<H', val[6:8])[0], '-',
                struct.unpack('<H', val[8:10])[0], '-',
                val[10], val[11], val[12], val[13], val[14], val[15])
        else:
            val_ = "%s%.08X%s%.04X%s%.04X%s%.04X%s%.02X%.02X%.02X%.02X%.02X%.02X%s" % (
                '{', struct.unpack('<I', val[0:4])[0], '-',
                struct.unpack('<H', val[4:6])[0], '-',
                struct.unpack('<H', val[6:8])[0], '-',
                struct.unpack('<H', val[8:10])[0], '-',
                val[10], val[11], val[12], val[13], val[14], val[15], '}')
        out.append(val_)

    return out

seeds = {
    0x6F3AD240: ['loader_reg_key', 'guuid'],
    0x91FA4E91: ['loader_reg_name', 'guuid'],
    0x350AF376: ['loader_enc_key', 'hex'],
    0x46ED5316: ['config_enc_key','key'],
    0x591AF903: ['config_reg_key','guuid'],
    0x5269AD4E: ['mutant', ['local', 'global', 'mutex']],
    0x93F4D91A: ['unknown','guuid'],
    0x6F6772E0: ['unknown','guuid'],
    0x6F6772E0: ['unknown','guuid'],
}

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('vsn', type=lambda x: int(x,0))
    parser.add_argument('computername')
    parser.add_argument('-v', '--verbose',
                        action='store_true')

    args = parser.parse_args()
    cn = args.computername.encode()
    vsn = args.vsn

    for k,v in seeds.items():
        vals = p_uuid(k, cn, vsn, v[1])
        for val in vals:
            print(f"cn: {cn.decode():s}; vsn: {vsn:#08x}; seed: {k:#08x}; desc: {v[0]}; val: {val}")

 
