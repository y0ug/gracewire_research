import sys, argparse, logging
import io, struct, cstruct

from grace_lib import *

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logging.basicConfig(level=logging.ERROR)
    
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--filename', required=True)
    parser.add_argument('-k', '--key', default='c3oeCSIfx0J6UtcV')
    args = parser.parse_args()

    fp = open(args.filename, 'rb')
    k = args.key.encode() 
    cipher = GraceAes(k) 

    data = cipher.decrypt_cbc(fp.read())
    sys.stdout.buffer.write(data)
