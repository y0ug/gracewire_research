import sys
import lznt1 

if __name__ == '__main__':
    fp = open(sys.argv[1], 'rb')
    data = fp.read()
    data = lznt1.decompress(data[4:]) 
    sys.stdout.buffer.write(data)
