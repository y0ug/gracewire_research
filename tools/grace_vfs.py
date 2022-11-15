import sys, argparse, logging
import io, struct, cstruct
import os

from grace_lib import *

logger = logging.getLogger(__name__)

def callback_ls(path, data):
    if type(data) == int: l = 4
    else: l = len(data)
    print(f'{l}\t{type(data)}\t{path}\t{VFS_StrData(data)}')

def callback_to_file(path, data):
    path = path[1:]
    fullpath = os.path.join('dump_vfs', path)
    folder = os.path.dirname(fullpath)
    print(f'{path} -> {fullpath}')
    os.makedirs(folder, exist_ok=True)
    if type(data) == bytes:
        open(fullpath, 'wb').write(data)
    else:
        open(fullpath, 'w').write(f'{data}')

if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)

    parser = argparse.ArgumentParser(description='print decrypted VFS')
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-d', '--dump', nargs='?', const=1, type=int)
    parser.add_argument('-v', '--verbose',
                        action='store_true')
    args = parser.parse_args()

    data = open(args.filename, 'rb').read()

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, force=True)

    fp = io.BytesIO(data)
    hd = VFS_ByteStreamHeaderPattern()
    hd.unpack(fp)
    print(hd)
    if args.dump:
        VFS_BuildPackMetaData32(fp, hd.dwHeaderLen, cb=callback_to_file) 
    else:
        VFS_BuildPackMetaData32(fp, hd.dwHeaderLen, cb=callback_ls) 



