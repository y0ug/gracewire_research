import sys
import socket, select
import io, struct, binascii
import cstruct
import time
import threading
import logging
import datetime
import json

config = {
    'cx': {
        'nid': '1CF094259E06664DA5504A5E1C551759',
        'dgx': 4,
        'exe': 2,
        'key': '',
        'port': 0xce5d
    },
    'va': {
        '45.129.137.237': 33964,
        '78.128.112.139': 33964,
    }
}

###
# Packet structure definition
###
class CStruct_(cstruct.CStruct):
    def __str__(self) -> str:
        result = []
        for field in self.__fields__:
            val = getattr(self, field, None)
            if type(val) in [ list, bytes] : val_s = ''.join(f'{x:02x}' for x in val)
            elif type(val) in [int] : val_s = hex(val)
            else: val_s = repr(val)
            result.append(field + "=" + val_s)
        return type(self).__name__ + "(" + ", ".join(result) + ")"

   
class NodePktHeader(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct NodePktHeader{
            uint8 bKey;
            uint8 bVersion;
            uint8 aNetworkId[16]; 
            uint8 aNodeId[16]; 
            uint8 bFrameId; 
            uint32 dwWaterMark; 
            uint32 dwCrc32;
        }
    """

    def _encrypt(self):
        self.aNetworkId = [x ^ self.bKey for x in self.aNetworkId]
        self.aNodeId = [x ^ self.bKey for x in self.aNodeId]
        data = [x ^ self.bKey for x in struct.pack('<I', self.dwWaterMark)]
        self.dwWaterMark = struct.unpack('<I', bytes(data))[0]

    def encrypt(self):
        self._encrypt()
        self.dwCrc32 = binascii.crc32(self.pack()[:-4])

    def decrypt(self):
        self._encrypt()

    def verify(self):
        crc32 = binascii.crc32(self.pack()[:-4])
        print(f'{type(self).__name__} CRC check {crc32:x} == {self.dwCrc32:x}')
        return crc32 == self.dwCrc32

class NodePktDataHeader(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN
    __def__ = """
        struct NodePktDataHeader{
            uint8 bCmdId;
            uint32 dwSessionId;
        }
    """

class NodePktRecordMeta(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct NodePktRecordMeta{
            struct NodePktDataHeader hdr;
            uint8 aRecordId[16]; 
        }
    """
    def encrypt(self, bKey):
        d = self.pack()
        return bytes([x ^ bKey for x in d])

class NodePktRecord(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct NodePktRecordMeta{
            struct NodePktDataHeader hdr;
            uint8 aRecordId[16]; 
        }
    """
    def encrypt(self, bKey):
        d = self.pack()
        return bytes([x ^ bKey for x in d])


class SingleDataPktHdr(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct SingleDataPktHdr{
            uint32 dwSize;
            uint32 dwCrc32;
        }
    """

class MultDataPktHdr(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct MultDataPktHdr{
            uint32 dwTotalLen;
            uint32 dwUnk; 
            uint32 dwCurId;
            uint32 dwTotal;
            uint32 dwCurDataOffset;
            uint32 dwSize;
            uint32 dwCrc32;
        }
    """


class NodePktInvitation(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct {
            struct NodePktDataHeader hdr;
            uint8 aInvitationId[16]; 
            uint8 aNodeId[16];
            uint16 wNodeBindedPort;
        }
    """

    def encrypt(self, bKey):
        d = self.pack()
        return bytes([x ^ bKey for x in d])

class NodeRcvRecord(CStruct_):
    __byte_order__ = cstruct.LITTLE_ENDIAN

    __def__ = """
        struct {
            struct NodePktDataHeader hdr;
            uint8 aRecordId[16]; 
        }
    """

    def encrypt(self, bKey):
        d = self.pack()
        return bytes([x ^ bKey for x in d])

##
# Unserilized data following Len Value
##
def unserialized(data):
    result = []
    fp = io.BytesIO(data)
    while True:
        x = fp.read(1)
        if len(x) == 0: break
        d = fp.read(ord(x))
        if len(d) == 1:
            d = ord(d)
        result.append(d)
    return result


###
# Bot Implementation
###
class P2PBot():
    def __init__(self):
        self.store = { 'node_id': None, 'cx': None, 'nodes': [], 'records': {} }

        self.pkt_cpt = 0
        self.status = False
        self.store_fn = 'store.json'

        self.whitelist = ['45.129.137.237' ]
        #self.whitelist = [ '140.206.183.45']
        try:
            with open(self.store_fn, "r") as outfile:
                logging.info(f'loading ctx from {self.store_fn}')
                self.store = json.load(outfile)
        except FileNotFoundError:
            pass


        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(10)

    def _send(self, data, addr):
        if len(self.whitelist) > 0 and addr[0] not in self.whitelist:
            return
        logging.info(f'{addr[0]}:{addr[1]} | send | size {len(data)} | {data.hex()}')
        self.s.sendto(data, addr)

    def init_store(self, config, node_id='1d37319760cfbc42b559833448f60ba6'):
        self.store['cx'] = config['cx']
        self.store['node_id'] = node_id
        for k,v in config['va'].items():
            n = { 'addr': (k, v), 'node_id': ''}
            self.store['nodes'].append(n)

    def start(self):
        addr = ('0.0.0.0', self.store['cx']['port'])
        logging.info(f'starting aNetworkId: {self.store["cx"]["nid"]} aNodeId: {self.store["node_id"]}')
        logging.info(f'listening on {addr[0]}:{addr[1]}')
        self.s.bind(addr)

        self.status = True
        self.pkt_cpt = 0

        logging.info(f'starting received thread')
        self.thr = threading.Thread(target=self.recv_loop)
        self.thr.start()

        for item in self.store['nodes']:
            addr = item['addr']
            self.send_invitation(addr)

    def wait(self):
        self.thr.join()

    def stop(self):
        try:
            logging.info(f'saving ctx to to {self.store_fn}')
            with open(self.store_fn, "w") as outfile:
                json.dump(self.store, outfile, indent=4, sort_keys=True)
        except Exception:
            logging.error("failed to write store to file", exc_info=True)

        logging.info(f'stopping bot')
        self.status = False
        self.s.close()
        self.thr.join()


    def recvfrom(self):
        pkt = NodePktHeader()

        # UDP packet size not framegmented is around MTU 1500/1460
        # UDP Header is 8bytes and IP header 20bytes
        # Node pkt header is 13 bytes
        # Max payload size 1460 - 20 - 8 - 13 = 1419bytes
        # that the size when it start fragmented msg with bFrameID 0xd 
        # the bot seem to framegment packet bigger then 1460 
        data, addr = self.s.recvfrom(2048)
        if len(self.whitelist) > 0 and addr[0] not in self.whitelist: 
            return None, None, None, None

        logging.info(f'{addr[0]}:{addr[1]} | recv | size {len(data)} | {data.hex()}')

        #open(f'data_recv_{self.pkt_cpt}.bin', 'wb').write(data)
        self.pkt_cpt += 1

        fp = io.BytesIO(data)

        pkt.unpack(fp.read(pkt.size))
        #pkt.verify()
        pkt.decrypt()
        logging.info(f'{addr[0]}:{addr[1]} | {pkt}')

        if len(data) <= pkt.size:
            return addr, pkt, None, None

        if pkt.bFrameId == 0xd:
            pkt_data = MultDataPktHdr()
        else:
            pkt_data = SingleDataPktHdr()

        pkt_data.unpack(data[len(pkt):len(pkt)+pkt_data.size])
        data = data[pkt.size+pkt_data.size:]
        dwCrc32Data = binascii.crc32(data)
        data = bytes([x ^ pkt.bKey for x in data])
        
        logging.info(f'[#] processing data {pkt_data} | dwCrc32Data: 0x{dwCrc32Data:x}')
        return addr, pkt, pkt_data, data


    def ask_record_meta(self, addr, record_id):
        pkt = NodePktHeader()
        pkt.bKey = 0x80
        pkt.bVersion = 0x37
        pkt.aNetworkId =  bytes.fromhex(self.store['cx']['nid'])
        pkt.aNodeId = bytes.fromhex(self.store['node_id']) # come from sandbox execution
        pkt.bFrameId = 0x7
        pkt.dwWaterMark = int(time.perf_counter()) & 0xffffffff

        req = NodePktRecordMeta()
        req.hdr.bCmdId = 0x7
        req.hdr.dwSessionId = int(time.perf_counter()) & 0xffffffff
        req.aRecordId = record_id

        logging.info(pkt)
        logging.info(req)

        pkt.encrypt()

        hd =  pkt.pack()
        payload = req.encrypt(pkt.bKey)

        hdPayload = struct.pack('<II', len(payload), binascii.crc32(payload))
        data = hd + hdPayload + payload

        self._send(data, tuple(addr))

    def ask_record(self, addr, record_id, number):
        pkt = NodePktHeader()
        pkt.bKey = 0x80
        pkt.bVersion = 0x37
        pkt.aNetworkId =  bytes.fromhex(self.store['cx']['nid'])
        pkt.aNodeId = bytes.fromhex(self.store['node_id']) # come from sandbox execution
        pkt.bFrameId = 0x7
        pkt.dwWaterMark = int(time.perf_counter()) & 0xffffffff

        req = NodePktRecord()
        req.hdr.bCmdId = 0x9
        req.hdr.dwSessionId = int(time.perf_counter()) & 0xffffffff
        req.aRecordId = record_id

        data = b'\x01' + bytes([number])  # it's serialized len and value

        logging.info(f'{addr[0]}:{addr[1]} | {pkt}')
        logging.info(f'{addr[0]}:{addr[1]} | {req}')

        pkt.encrypt()

        hd =  pkt.pack() 
        payload = bytes([x ^ pkt.bKey for x in req.pack() + data])

        hdPayload = struct.pack('<II', len(payload), binascii.crc32(payload))
        data = hd + hdPayload + payload

        self._send(data, tuple(addr))

    def send_invitation(self, addr):    
        pkt = NodePktHeader()
        pkt.bKey = 0x80
        pkt.bVersion = 0x37
        pkt.aNetworkId =  bytes.fromhex(self.store['cx']['nid'])
        pkt.aNodeId = bytes.fromhex(self.store['node_id'])
        pkt.bFrameId = 0x7
        pkt.dwWaterMark = int(time.perf_counter()) & 0xffffffff


        req = NodePktInvitation()
        req.hdr.bCmdId = 0x1
        req.hdr.dwSessionId = int(time.perf_counter()) & 0xffffffff
        req.aInvitationId = bytes.fromhex('e1bce7bc8cd00f438889122eebc7d329')
        req.aNodeId = bytes.fromhex(self.store['node_id'])
        req.wNodeBindedPort = self.store['cx']['port']

        logging.info(f'{addr[0]}:{addr[1]} | {pkt}')
        logging.info(f'{addr[0]}:{addr[1]} | {req}')

        pkt.encrypt()

        hd =  pkt.pack()
        payload = req.encrypt(pkt.bKey)

        hdPayload = struct.pack('<II', len(payload), binascii.crc32(payload))
        data = hd + hdPayload + payload

        self._send(data, tuple(addr))

   
    def recv_loop(self): 
        while self.status:
            try:
                addr, pkt, pkt_data, data = self.recvfrom()
                if addr == None: continue

                self.pkt_handler(addr, pkt, pkt_data, data)

                # We need to echo the header we received
                if pkt.bFrameId != 0x10:
                    pkt.bFrameId = 0x10
                    pkt.encrypt()
                    data = pkt.pack()
                    self._send(data, addr)
            except socket.timeout:
                pass

    def pkt_handler(self, addr, pkt, pkt_data, data):
        if pkt.bFrameId == 0x10:
            logging.info(f'[#] echo recv')
        elif pkt.bFrameId == 0x7:
            logging.info(f'[#] fit one packet')
            hdr = NodePktDataHeader()
            hdr.unpack(data)
            logging.info(f'{hdr}')
            if hdr.bCmdId == 0x1:
                logging.info(f'  [#] invitation packet')
                inv = NodePktInvitation()
                inv.unpack(data)
                logging.info(f'  {inv}')
            elif hdr.bCmdId == 0x2:
                logging.info(f'  [#] add node to probes')
                inv = NodePktInvitation()
                inv.unpack(data)
                logging.info(f'  {inv}')
            elif hdr.bCmdId == 0x03:
                logging.info(f'  [#] Get a ping request')
                node_info = unserialized(data[hdr.size:])
                logging.info(f'  node_info: {node_info} | {node_info[1]}/{node_info[0]} connections | {node_info[2]} records')
                # @todo implement response
            elif hdr.bCmdId == 0x4:
                logging.info(f'  [#] node info')
                node_info = unserialized(data[hdr.size:])
                logging.info(f'  node_info: {node_info} | {node_info[1]}/{node_info[0]} connections | {node_info[2]} records')
            elif hdr.bCmdId == 0x05: 
                logging.info(f'  [#] Get a new node')
                fp = io.BytesIO(data[hdr.size:])
                node_id = fp.read(0x10)
                node_port = struct.unpack('<H', fp.read(2))[0]
                node_ip = fp.read(ord(fp.read(1))).decode()
                logging.info(f'  node_id: {node_id.hex()} node: {node_ip}:{node_port:d}')
                n = { 'addr': [node_ip, node_port], 'node_id': node_id.hex()}

                is_exist = False
                for v in self.store['nodes']:
                    if v['node_id'] == node_id.hex():
                        is_exist = True
                        break

                if not is_exist: 
                    logging.info(f'  adding node to store')
                    self.store['nodes'].append(n)
                    self.send_invitation(n['addr'])


            elif hdr.bCmdId == 0x06:
                logging.info(f'  [#] Get a record metadata')
                record_id =  data[hdr.size:hdr.size+0x10]
                record_info = unserialized(data[hdr.size+0x10:])
                logging.info(f'  record_id: {record_id.hex()} record_info: {record_info}')
            elif hdr.bCmdId == 0xa:
                logging.info(f'  [#] Get a record')
                r = NodePktRecord()
                r.unpack(data)
                logging.info(f'  {r}')

            else:
                logging.info(f'  [#] unsupported hdr.bCmdId 0x{hdr.bCmdId:x}')
        elif pkt.bFrameId == 0xd:
            open(f'record_{pkt_data.dwUnk}_{pkt_data.dwCurId}_{pkt_data.dwTotal}.bin', 'wb').write(data)
            pass
        else:
            logging.info(f'[#] unsupported pkt.bFrameId 0x{pkt.bFrameId:x}')

###
# Used to debug pkt processing
###
def pkt_process(data):
    pkt = NodePktHeader()
    pkt.unpack(data)
    pkt.decrypt()
    logging.info(f'{pkt}')



    if len(data) <= len(pkt):
        return pkt, None

    if pkt.bFrameId == 0xd:
        pkt_data = MultDataPktHdr()
    else:
        pkt_data = SingleDataPktHdr()

    pkt_data.unpack(data[len(pkt):len(pkt)+pkt_data.size])
    data = data[pkt.size+pkt_data.size:]
    dwCrc32Data = binascii.crc32(data)
    data = bytes([x ^ pkt.bKey for x in data])

    logging.info(f'[#] processing data {pkt_data} | dwCrc32Data: 0x{dwCrc32Data:x}')

    return pkt, pkt_data, data

def unit_test():
    import unittest.mock
    with unittest.mock.patch('socket.socket'):
        bot = P2PBot(config)
        datas =[
            '57374ba7c372c951311af2071d094b02400e1788b79a31122111e4ce5ccc7637a17507a068fc02f2abca6f0b000000623cae75548f45a839568d56ce5655'
            'a837b4583c8d36aecee50df8e2f6b4fdbff1e8774865ceeddeee1b31a33389c85e8a07347d346ef374522a21000000d9bc157fae70ba57c631dbd05471f102e021941b132cfcb0e9a0287659f994fa7fa9a9b6aa',
            'de37c22e4afb40d8b8937b8e9480c28bc9879e013e13b89ba8986d47d545ffbe28fc0747e026d45a24ad4221000000f9116c7bd806cc21b065634eeb6c7d10916c7bbd2b22bbac01d6aea5258fe28c09dfdfcfdc',
            '56374aa6c273c850301bf3061c084a03410f1689b69b30132010e5cf5dcd7736a0740704192081348e12b6260000006a719d99534e45c2eceeb179491408a31dec24bcdecc56c6a90b98586762667864666078676e65786267',
            'bd37a14d299823bbdbf018edf7e3a1e8aae4fd625d70dbf8cbfb0e24b6269cdd4b9f07657cd10f1705a6af26000000e25f43ceb8a5ae2907be54693346f8b9f0331044f7d8ac536be073b38c898d938f8d8b938c858e938989',
            'a837b4583c8d36aecee50df8e2f6b4fdbff1e8774865ceeddeee1b31a33389c85e8a07c1bb155366213fda2600000026dba253adb0bb3c12624f089973e392ec39ad059a9c38aed2f566a6999c98869a989e8699909b869c9e',
            '2b3737dbbf0eb52d4d668e7b6175377e3c726bf4cbe64d6e5d6d98b220b00a4bdd0907e0674fbc1fe0073a26000000e87bea4e2e3338bf912a441afca347ee64a4708ad6b2c05a3376e5251a131b051a1d13051d19051a1b1d',
            'fa37e60a6edf64fc9cb75faab0a4e6afeda3ba251a379cbf8cbc4963f161db9a0cd807c1f941c797095cfe260000007e04c2e3ffe2e96e4091746e5c9415f0b4687758752e9d08c8a734f4cbcecad4c8caccd4cbc2c9d4c9cc',
            '92378e6206b70c94f4df37c2d8cc8ec785cbd24d725ff4d7e4d4210b9909b3f264b007597e3e5f8250f0eb26000000e3261b83978a810628cf81a14d9ca7ffdd034d0fdb228ce594cf5c9ca3a6a2bca0a2a4bca3aaa1bca1aa',
            '26373ad6b203b820406b83766c783a73317f0e57add7580d0d68864fb2e30714935a07f9f4b6f8c778cd7727000000d079bd6127dcc92635dd305179f97ef063ac01e5fc505b44330e57add7580d0d68864fb2e30714935a7be8',
            '3b3727cbaf1ea53d5d769e6b7165276e2c62134ab0ca451010759b52affe1a098e4707363d0f0024ea3011270000002599062f3ac6d03b28c02d4c64e463ed7eb11cf8e14d46592e134ab0ca451010759b52affe1a098e4766f5',
            'bb37a74b2f9e25bdddf61eebf1e5a7eeace258351608e32652f50677f50996dcde4e07ae6753c6ca2adec40b000000fab9f991bf494c12ffbab3ba99bab9' 
            '65377995f140fb630328c0352f3b7930723c86ebc8d63df88c2bd8a92bd7480200900d300d17c6ae0c47a94c110000010000000000000004000000000000008b05000054ae1e696d67530469fc161d99bc3ccf2dec59d6dee1317d2465a1f89183666565657d6565656565656565656565656565656565656542656565656565656565657e666565656565655f65656565616508001104086565652865656545656565666566650b0011542623555c5157505c205553535351212450505551245020542650505452505cfa6565651a65656545656565666567650c015c5c5256525d2326215c505c2424515d5d5c5626275627275d515051545d5154dd656565d76565656365656566656665110402101501041100b6656565ae6565656d65656567656665161104e5bb94345937b2648a656565826565656d65656567656165090a040150ba6465656565656f646565676465656d65656567656665160b06c59280345937b26440646565786465656d656565676566651011096565656565656565216465655d6465656965656566656665100b0c1015010411004b07090a060e1264656532646565456565656665666515120121515d532727572324275254272751515d57542456575254575126245c575656ee676565ee646565656465656565616516000409ec0a1c88c751992980102b97162881b721871bf718c0101c5dadd5504f4c83b7fb088ae4d1538660a759a456a9dca6b60e8dcbf84d1ab72da7556026e0ab6581b1942ab05f60cee8e9d3689b2a10196cd840a115a4a3390d72e140a2381faf714ea0efacc6becc77cb344180132aa5b71c3d50e00cbf87c6e7d03c998f28e2320a62fcb407f3d73b1ec34d0fe15b593db49cccd444cf8b18095644f875a1b5a860bf5b9a80cada4e3c8a5a402ebb3fb562db40e697f605f96d515a907b17c293a4373d17f8f04f646140428141d034703c0b929e1750afc7419620bba145717107c99c5dfd03912c8cf8b3ac6cf2c75c7b63389fbd5ca8043f95d5d265a18c1f65656565fb6765651865656565656665060302a1f89183666565657d6565656565656565656565656565656565656565656565426565656565653c6565655c65656545656565666567650315275d5d52535621235d56545d23515c53572355202321565c5d57565121235c530e6565656465656561656565646567651716656565656565656561656565646567650801bb756565336665654b6665656561650d04160d276665656165656561656565646561650102161165656565456565656165656564656165160c1f00ac666565656565650366656565646555e46665651c6665656d656565676566650a03166565656565656565f0666565657565656165656564656165160c1f0065656565cc66656545656565656561650d04160de7ebc7c312dae502796efc32a64cfcc0dcf674f85c6f987791569661fc5562115961656565656565bc6665656564655491666565896665656d656565676566650a031665756565656565656d616565657565656165656564656165160c1f00656565657961656545656565656561650d04160d58e74757b23bdee85f3e8e8a9c79dea53527a3ee6b320709e4fd743041862357ca616565656565652961656565646557026165653a6165656d656565676566650a031665456565656565651e616565657565656165656564656165160c1f0065656565ea61656545656565656561650d04160d1199e79e8128188471d483176a9522db49d042c96197337d166340fd71ab393a4760656565656565da61656565646556bf616565b76165656d656565676566650a031665556565656565658b616565657565656165656564656165160c1f00656565656760656545656565656561650d04160d2b309765fb0454e8130ca9e7d65deba51729fa64c7cc0c1b50e862eccd27f850f060656565656565576065656564655128606565206065656d656565676566650a0316652565656565656504606565657565656165656564656165160c1f00656565651060656545656565656561650d04160d',
            'c637da3652e358c0a08b63968c98da93d19f25486b759e5b2f887b0a8874eba1a3330dee082a4f17d9020d4c1100000100000001000000040000008b0500008b050000982878fee5ac5a216a2c014ccc36315e53fac797377e9501c015d401480ca5ae05475639cec0c6c6c6c6c6c663c3c6c6c6c7c6f306c3c6c67ec3c6c6cec6c6c6c4c6c5c6a9a0b5c696c6c6c6c6c6c612c3c6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c62ec3c6c6e6c6c6c6c6c6c2c6aea7b5ae7f5167ac8dfa6eafa8ef9414414a8a948e173cf4d0ccc0c3c0fbab84fb9ba999bdc0c6c6c6c6c6c6dec0c6c6c6c7c6f0f5c0c6c6edc0c6c6cec6c6c6c4c6c5c6a9a0b5c6a6c6c6c6c6c6c681c0c6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c69dc0c6c6e6c6c6c6c6c6c2c6aea7b5ae1083afaa61724ac87251571d4885d3f3b52f5a869889d63bfe5c4ca1ba234d1528c0c6c6c6c6c6c64dc0c6c6c6c7c6f160c0c6c658c0c6c6cec6c6c6c4c6c5c6a9a0b5c6b6c6c6c6c6c6c67cc0c6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c608c0c6c6e6c6c6c6c6c6c2c6aea7b5ae2cc0769180c03893ae23e0a9336dcf8edb0d73895b7cb209714b842b0ca47367a7c1c6c6c6c6c6c638c0c6c6c6c7c6fedfc1c6c6d7c1c6c6cec6c6c6c4c6c5c6a9a0b5c646c6c6c6c6c6c6ebc1c6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c687c1c6c6e6c6c6c6c6c6c2c6aea7b5ae27ecc010eb6b235d0df950d7304e404819a775bf57e2dee7db560ee5c9be321a12c1c6c6c6c6c6c6b7c1c6c6c6c7c6ff4ac1c6c642c1c6c6cec6c6c6c4c6c5c6a9a0b5c656c6c6c6c6c6c666c1c6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c672c1c6c6e6c6c6c6c6c6c2c6aea7b5ae8c509dc369b5f4972be071e23ecc8ad40b2ec722ff198649ca332ace1dd1ff5581cec6c6c6c6c6c622c1c6c6c6c7c68739c1c6c631c1c6c6cec6c6c6c4c6c5c6a9a0b5c666c6c6c6c6c6c6d5cec6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c6e1cec6c6e6c6c6c6c6c6c2c6aea7b5ae1f5a628a78252f414c145f8c2096f25c64005647bc633187f534de64330020767ccec6c6c6c6c6c691cec6c6c6c7c684b4cec6c6accec6c6cec6c6c6c4c6c5c6a9a0b5c676c6c6c6c6c6c640cec6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c65ccec6c6e6c6c6c6c6c6c2c6aea7b5aebaba3dfad69f089025855164068368d0ed1b0d9888c426566239a6b5c452d4c6ebcfc6c6c6c6c6c60ccec6c6c6c7c68523cec6c61bcec6c6cec6c6c6c4c6c5c6a9a0b5c606c6c6c6c6c6c63fcec6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c6cbcfc6c6e6c6c6c6c6c6c2c6aea7b5aeeff10b8838044605f43392b3a6450315f7c718448ffce90047fab1f0b190ad0b66cfc6c6c6c6c6c6fbcfc6c6c6c7c6829ecfc6c696cfc6c6cec6c6c6c4c6c5c6a9a0b5c616c6c6c6c6c6c6aacfc6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c646cfc6c6e6c6c6c6c6c6c2c6aea7b5ae631a37824059465ab971820bdf2c179733697d0db07eb4449e29face191c3d15d5ccc6c6c6c6c6c676cfc6c6c6c7c6830dcfc6c605cfc6c6cec6c6c6c4c6c5c6a9a0b5c626c6c6c6c6c6c619cfc6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c635cfc6c6e6c6c6c6c6c6c2c6aea7b5ae092ceaebef3ee7a6feec116d8391e0b02e183c2de193323c53de70f50c00937940ccc6c6c6c6c6c6e5ccc6c6c6c7c680f8ccc6c6f0ccc6c6cec6c6c6c4c6c5c6a9a0b5c636c6c6c6c6c6c694ccc6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c6a0ccc6c6e6c6c6c6c6c6c2c6aea7b5ae459af7918f40dcb74eb81b1903ed5df5d6c0f238c5d6254051089dae77f509e53cccc6c6c6c6c6c651ccc6c6c6c4c6f7f674ccc6c66cccc6c6cec6c6c6c4c6c5c6a9a0b5c6c6c7c6c6c6c6c600ccc6c6c6d6c6c6c2c6c6c6c7c6c2c6b5afbca3c6c6c6c61cccc6c6e6c6c6c6c6c6c2c6aea7b5ae14276ae945233f241518d7ff272272f273fbc85a9b5ce0d48d9f5424504460d6a8cdc6c6c6c6',
            'aa37b65a3e8f34accce70ffae0f4b6ffbdf349240719f23743e41766e41887cdcf5f0db4b86f13a24815034c110000010000000200000004000000160b00008b05000065374d3caaaaa1a1aaaaaaa8aa9b9b8ca1aaaab4a1aaaaa2aaaaaaa8aaa9aac5ccd9aabaabaaaaaaaaaa90a1aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaae4a1aaaa8aaaaaaaaaaaaeaac2cbd9c25c1d4720702a47ac2403633696bfc77daddd4dbcf65bae09d680a1419736baf348a1aaaaaaaaaaaad5a1aaaaaaa8aa9b9830a1aaaa38a1aaaaa2aaaaaaa8aaa9aac5ccd9aa8aabaaaaaaaaaa04a1aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa68a1aaaa8aaaaaaaaaaaaeaac2cbd9c2a9bb5552417f1098e567c33a5ff466204ebb4ca78b8072cb6f39f5fbc413a030fca6aaaaaaaaaaaa59a1aaaaaaa8aa9b99a4a6aaaaaca6aaaaa2aaaaaaa8aaa9aac5ccd9aa9aabaaaaaaaaaa88a6aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa9ca6aaaa8aaaaaaaaaaaaeaac2cbd9c29677f3b947e3bb0a7b006f7348e36e43eb2ca70f29efab02a7715b9e1300758060a6aaaaaaaaaaaacda6aaaaaaa8aa9b9e28a6aaaad0a6aaaaa2aaaaaaa8aaa9aac5ccd9aaeaabaaaaaaaaaa3ca6aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa00a6aaaa8aaaaaaaaaaaaeaac2cbd9c2078fd4cf66ff163d5f4d894df1b1799c3cb1639677a3ccf65f717fdc65026db094a7aaaaaaaaaaaa71a6aaaaaaa8aa9b9f5ca6aaaa44a6aaaaa2aaaaaaa8aaa9aac5ccd9aafaabaaaaaaaaaaa0a7aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaab4a7aaaa8aaaaaaaaaaaaeaac2cbd9c244485d986f20e0a6c3e5f952f15611923e192dfe2242b3ec8aa99f4d2343c29018a7aaaaaaaaaaaae5a7aaaaaaa8aa9b9cc0a7aaaac8a7aaaaa2aaaaaaa8aaa9aac5ccd9aacaabaaaaaaaaaad4a7aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa38a7aaaa8aaaaaaaaaaaaeaac2cbd9c29b3a61df759d117ca07252b21c58b24a1afc43e64c1aa8b0dbba693f64c5900a8ca4aaaaaaaaaaaa69a7aaaaaaa8aa9b9d74a7aaaa7ca7aaaaa2aaaaaaa8aaa9aac5ccd9aadaabaaaaaaaaaa58a7aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaaaca4aaaa8aaaaaaaaaaaaeaac2cbd9c2701646f039c07020d3be7ff56e0d0f884c5429e2e99da76c4af8aa99161ef26230a4aaaaaaaaaaaa9da4aaaaaaa8aa9b92f8a4aaaae0a4aaaaa2aaaaaaa8aaa9aac5ccd9aa2aabaaaaaaaaaacca4aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaad0a4aaaa8aaaaaaaaaaaaeaac2cbd9c2257753ce6ab5db9af54d1b53844645b262303ac76839753cf7b04f5916cabbc1a4a5aaaaaaaaaaaa01a4aaaaaaa8aa9b936ca4aaaa14a4aaaaa2aaaaaaa8aaa9aac5ccd9aa3aabaaaaaaaaaa70a4aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa44a4aaaa8aaaaaaaaaaaaeaac2cbd9c24785892f5e5b548370c24ef9dd075368bb5ddf83d080c6cff7ba9ae87b434f8b28a5aaaaaaaaaaaab5a5aaaaaaa8aa9beb90a5aaaa98a5aaaaa2aaaaaaa8aaa9aac5ccd9aa0aabaaaaaaaaaae4a5aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaac8a5aaaa8aaaaaaaaaaaaeaac2cbd9c22298cad2805952f62aafc797949e060123c04394c860839c0c82025eaaa81abd5ca5aaaaaaaaaaaa39a5aaaaaaa8aa9be804a5aaaa0ca5aaaaa2aaaaaaa8aaa9aac5ccd9aa1aabaaaaaaaaaa68a5aaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaa7ca5aaaa8aaaaaaaaaaaaeaac2cbd9c268799c864140e46ee8ee067358c14b389fd4ac2f71bcea6d8161144e1c627193c0baaaaaaaaaaaaaadbaaaaaaaa8aa9be988baaaaab0baaaaaa2aaaaaaa8aaa9aac5ccd9aa6aabaaaaaaaaaa9cbaaaaaaabaaaaaaeaaaaaaabaaaeaad9c3d0cfaaaaaaaae0baaaaa8aaaaaaaaaaaaeaac2cbd9c25c965fe57a03b4d0d7ccf5e8b86dcdb6d37428f9c293c06cb752f287588e0725aaaaaaaaaaaaaaaad1baaaaaaaa8aa9bee3cbaaaaa24baaaaaa2aaaaaaa8aaa9aa'
        ]
        i = 0;
        for d in datas:
            data = bytes.fromhex(d)
            pkt, pkt_data, data = pkt_process(data)
            bot.pkt_handler(("127.0.0.1", 1337), pkt, pkt_data, data)
            open(f'unknown_{i}.bin', 'wb').write(data)
            i += 1

def unit_test2():
    import unittest.mock
    with unittest.mock.patch('socket.socket'):
        bot = P2PBot()
        datas =[
            'f937e5096ddc67ff9fb45ca9b3a7e5aceea0f86ec24022552eb473e9a0fedb8c2e8007feb28eca7abc0bd21500000092148f37fe7b5151a6608a810520a053b170c54a427dade1b8',
            '50374ca0c475ce56361df5001a0e4c05470951c76be98bfc871dda40095772258729079905d866a24da98c170000000c51595959d2f8f80fc92328ac8909fa18d96ce3ebd40448115151',
            'a637ba56328338a0c0eb03f6ecf8baf3b1ffa7319d1f7d0a71eb2cb6ffa184d371df077f2d60ccaee8a5d017000000658bd2bfaf240e0ef93fd5de5a7fff0cee2f9a151d22f2bee7a7a5',
            '80379c7014a51e86e6cd25d0cade9cd597d99db7b117e04f3cc235d903b4c8768b2607c12a87801a7b23000100150000001f0a643689c12a878019f3f87c59d92ac809bc333b04d498c1',
            '80379c7014a51e86e6cd25d0cade9cd597d99db7b117e04f3cc235d903b4c8768b2607c32a878091b32aaa010115000000937caafc89c32a878019f3f87c59d92ac809bc333b04d498c1',

        ]
        i = 0;
        for d in datas:
            data = bytes.fromhex(d)
            pkt, pkt_data, data = pkt_process(data)
            bot.pkt_handler(("127.0.0.1", 1337), pkt, pkt_data, data)
            open(f'unknown_{i}.bin', 'wb').write(data)
            i += 1

def emulate():
    bot = P2PBot()
    bot.init_store(config)
    bot.start()
    time.sleep(10)

    #bot.ask_record_meta(('45.129.137.237', 33964), bytes.fromhex('bbbd9035b2a3ce4fb2a563f5fc6572df'))
    #bot.send_invitation(('140.206.183.45', 52829))
    #bot.ask_record(('45.129.137.237', 33964), b'<\xf5\xf3\xe2\x91\xd3\x07\x05\xdb8\xde_\xb3\x12E\xe29*\x17-\x87.\xe4\xd10\xe28~\xd9\xaa_3')

    bot.ask_record(('45.129.137.237', 33964), bytes.fromhex('997378FCD959AA48893CB3BB84541841'), 0)
    time.sleep(2)
    bot.ask_record(('45.129.137.237', 33964), bytes.fromhex('997378FCD959AA48893CB3BB84541841'), 1)
    time.sleep(2)
    bot.ask_record(('45.129.137.237', 33964), bytes.fromhex('997378FCD959AA48893CB3BB84541841'), 3)
    try:
        bot.wait()
    except KeyboardInterrupt:
        bot.stop()

if __name__ == "__main__":
    logging.basicConfig(level = logging.INFO,
        format="%(asctime)s:%(module)s:%(levelname)s:%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S %Z",
        handlers=[
            logging.FileHandler(f'debug_{datetime.datetime.now().strftime("%Y%m%d%H%M%S")}.log'),
            logging.StreamHandler(sys.stdout)
        ])
    try:
        #unit_test2()
        emulate()
    except Exception:
        logging.error("fatal error", exc_info=True)
        raise
