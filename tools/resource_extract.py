import pefile
import sys
import os
import re
from Crypto.Cipher import AES


if __name__ == "__main__":
    pe = pefile.PE(sys.argv[1])
    e =  pe.DIRECTORY_ENTRY_RESOURCE.entries
    e = e[0].directory.entries[0].directory.entries[0]
    offset = e.data.struct.OffsetToData
    size = e.data.struct.Size
    #print(offset, size)
    data = pe.get_data(offset, size)
    sys.stdout.buffer.write(data)
