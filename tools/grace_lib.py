import sys, logging
import io, struct

import pefile
import aes # https://raw.githubusercontent.com/boppreh/aes/master/aes.py
import cstruct

logger = logging.getLogger(__name__)

###
# Grace VFS parsing
###
class CStruct_(cstruct.CStruct):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    def __str__(self) -> str:
        result = []
        for field in self.__fields__:
            val = getattr(self, field, None)
            if isinstance(val, list): val_s = ''.join(f'{x:02x}' for x in val)
            else: val_s = hex(val)
            result.append(field + "=" + val_s)
        return type(self).__name__ + "(" + ", ".join(result) + ")"

class VFS_ByteStreamHeaderPattern(CStruct_):
    __def__ = """
        struct {
            uint32_t magic;
            uint16_t fixed4;
            uint8_t m64BitFlag;
            uint8_t dummy0;
            uint64_t dwHeaderLen;
            uint64_t zero;
        }
    """

class VFS_SerializedEntry32(CStruct_):
    __def__ = """
        struct {
            uint32_t dwNextEntryStreamPos;
            uint32_t dwDataStreamPos;
            uint32_t dwSerializedSize;
            uint8_t bValueType;
            uint8_t bEntryNameIsWideString;
            uint8_t wEntryNameLen;
            uint8_t dummy;
        }
    """

class VFS_SerializedPack32(CStruct_):
    __def__ = """
        struct {
            uint32_t dwStreamPos_NextSiblingPack;
            uint32_t dwStreamPos_FirstChildPack;
            uint32_t dwStreamPos_FirstEntry;
            uint8_t bEntryNameIsWideString;
            uint8_t wEntryNameLen;
            uint8_t dummy;
        }
    """

class VFS_SerializedPack64(CStruct_):
    __def__ = """
        struct {
            uint64_t dwStreamPos_NextSiblingPack;
            uint64_t dwStreamPos_FirstChildPack;
            uint64_t dwStreamPos_FirstEntry;
            uint8_t bEntryNameIsWideString;
            uint16_t wEntryNameLen;
        }
    """


def VFS_StrData(data):
    if isinstance(data, bytes):
        return f'{data[0:0x10]}'
    elif isinstance(data, int):
        return f'0x{data:x}'
    else:
        return f'{data}'


def VFS_UnserializedData(fp, se):
    fp.seek(se.dwDataStreamPos)
    if se.bValueType == 0: # Bytes
        return fp.read(se.dwSerializedSize)
    elif se.bValueType == 1: # Int
        return se.dwDataStreamPos
        #return struct.unpack('<I', fp.read(se.dwSerializedSize))[0]
    elif se.bValueType == 2: # Int64
        return struct.unpack('<Q', fp.read(se.dwSerializedSize))[0]
    elif se.bValueType == 3: # String
        return fp.read(se.dwSerializedSize).decode()
    elif se.bValueType == 4: # WString
        return fp.read(se.dwSerializedSize).decode()
    return None

def VFS_BuildEntryMetaData32(fp, pos, depth=0, path='', cb=None):
    s = VFS_SerializedEntry32()
    while(True):
        fp.seek(pos)
        try:
            s.unpack(fp)
        except:
            return

        name = fp.read(s.wEntryNameLen)
        try:
            name = name.decode()
        except:
            logger.debug('failed to decode name')
            pass

        try:
            data = VFS_UnserializedData(fp, s)
            try:
                if cb: cb(f'{path}/{name}', data) 
            except Exception:
                logger.exception("cb")

            logger.debug(f'{" " * depth}entry 0x{pos:08x} | name = {name} | {VFS_StrData(data)}')
        except:
            logger.exception("failed to UnserializedData")
            logger.debug(f'{" " * depth}entry 0x{pos:08x} | name = {name}')
        if not s.dwNextEntryStreamPos:
            return

        pos = s.dwNextEntryStreamPos

def VFS_BuildPackMetaData32(fp, pos, depth=0, path='', cb=None):
    s = VFS_SerializedPack32()
    while(True):
        fp.seek(pos)
        s.unpack(fp)

        fp.seek(pos + s.size -1)
        name = fp.read(s.wEntryNameLen)
        try:
            name = name.decode()
        except:
            pass

        # First name is empty so we want to avoid //
        if name != '':
            path_ = f'{path}/{name}'
        else:
            path_ = ''

        logger.debug(f'{" " * depth}pack 0x{pos:08x} | name = {name}')

        if s.dwStreamPos_FirstEntry:
            VFS_BuildEntryMetaData32(fp, s.dwStreamPos_FirstEntry, depth+1, path_, cb)
        if s.dwStreamPos_FirstChildPack:
            VFS_BuildPackMetaData32(fp, s.dwStreamPos_FirstChildPack, depth+1, path_, cb)
        if not s.dwStreamPos_NextSiblingPack:
            return
        
        pos = s.dwStreamPos_NextSiblingPack

###
# Grace custom AES
###
class GraceAes(aes.AES):
    def decrypt_cbc(self, data):
        fp = io.BytesIO(data)
        dwLen = len(data)

        previous = fp.read(0x10)
        dst = b'' 

        while True:
            if fp.tell() >= dwLen - 0x20:

                # Read last full block and decrypt it
                d = fp.read(0x10)
                val = self.decrypt_block(d)

                # Read the final block and xor with decrypted last full block
                d2 = fp.read(0x10)
                val2 = aes.xor_bytes(val, d2)

                # Append the decrypted block bytes to get a full block
                d2 += bytes(val[-(0x10-len(d2)):])

                # decrypt and CBC
                val = self.decrypt_block(d2)
                val = aes.xor_bytes(previous, val)

                dst += val
                dst += val2
                break
                # last case


            d = fp.read(0x10)
            val = self.decrypt_block(d) # decrypt
            val = aes.xor_bytes(previous, val) # do CBC
            dst += val
            previous = d

        return dst

def PeExtractRsrc(fn):
    pe = pefile.PE(fn)
    e =  pe.DIRECTORY_ENTRY_RESOURCE.entries
    e = e[0].directory.entries[0].directory.entries[0]
    offset = e.data.struct.OffsetToData
    size = e.data.struct.Size
    data = pe.get_data(offset, size)
    return data

