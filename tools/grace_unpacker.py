import sys, argparse
import pefile
import struct

class GraceUnpacker(object):
    def __init__(self):
        cmds = [ c  for c in dir(self) if not c.startswith('_')]

        parser = argparse.ArgumentParser(description='Gracewire/Flawedgrace some static unpacker')
        parser.add_argument('command', help='Subcommand to run', choices=cmds)
        args = parser.parse_args(sys.argv[1:2])
        getattr(self, args.command)()

    def unpack(self):
        parser = argparse.ArgumentParser(description='Simple unpacker')
        parser.add_argument('-f', '--filename', required=True)
        parser.add_argument('-o', '--offset', default=0x6000, type=lambda x: int(x,0))
        args = parser.parse_args(sys.argv[2:])

        pe = pefile.PE(args.filename)
        offset = args.offset
        #offset = int(args.offset, 16)
        dwPayloadSize = struct.unpack('<I', pe.get_data(offset, 4))[0]
        data = pe.get_data(offset, dwPayloadSize)
        key = data[4:60]
        data = data[60:]

        #data_ = [ data[i] ^ key[i%len(key)]  ^ (i&0xff) for i in range(len(data)) ]
        # Buggued XOR after first iteration key start a idx 1 due to increment after reset to 0
        j = 0
        data_ = [] 
        for i in range(len(data)):
            x = data[i] ^ key[j] ^ (i & 0xff)
            data_.append(x)
            if j == len(key) - 1: j = 0
            j += 1

        data_ = b'MZ\x00\x00' + key + bytes(data_)
        sys.stdout.buffer.write(data_)
        #print(f'{dwPayloadSize:x} {len(data):x}')

    def unpack2(self):
        parser = argparse.ArgumentParser(description='Simple unpacker')
        parser.add_argument('-f', '--filename', required=True)
        parser.add_argument('-k', '--key', required=True)
        parser.add_argument('-o', '--offset', default=0x6000, type=lambda x: int(x,0))
        args = parser.parse_args(sys.argv[2:])

        pe = pefile.PE(args.filename)
        offset = args.offset
        #offset = int(args.offset, 16)
        dwPayloadSize = struct.unpack('<I', pe.get_data(offset, 4))[0]
        data = pe.get_data(offset + 4, dwPayloadSize-4)
        key = bytes.fromhex(args.key)
        key2 = data[0]
        data = data[1:]

        #data_ = [ data[i] ^ key[i%len(key)]  ^ (i&0xff) for i in range(len(data)) ]
        # Buggued XOR after first iteration key start a idx 1 due to increment after reset to 0
        j = 0
        data_ = [] 
        for i in range(len(data)):
            x = data[i] ^ key[j] ^ key2 
            data_.append(x)
            if j == len(key) - 1: j = 0
            j += 1

        data_ = b'MZ\x00\x00\x03' + bytes(data_)
        sys.stdout.buffer.write(data_)
        #print(f'{dwPayloadSize:x} {len(data):x}')


if __name__ == '__main__':
    GraceUnpacker()