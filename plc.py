import dcp
import rpc

from util import *
from protocol import *

def main():
    s = socket(AF_PACKET, SOCK_RAW)
    s.bind((s.gethostname(), 3))
    while(True):
        #先接收发现报文，建立连接
        data, addr = s.recvfrom(4096)
        eth = EthernetVLANHeader(data)
        if eth.dst != get_mac(s.gethostname()) or eth.type != PNDCPHeader.ETHER_TYPE:
            continue
        print("MAC address:", mac2s(eth.src))

        # nur DCP Identify Responses
        pro = PNDCPHeader(eth.payload)
        if not (pro.service_type == PNDCPHeader.REQUEST):
            continue

        # Blöcke der Response parsen
        blocks = pro.payload
        length = pro.length
        parsed = {}

        while length > 6:
            block = PNDCPBlock(blocks)
            blockoption = (block.option, block.suboption)
            parsed[blockoption] = block.payload

            block_len = block.length
            if blockoption == PNDCPBlock.NAME_OF_STATION:
                print("Name of Station: %s" % block.payload)
                parsed["name"] = block.payload
            elif blockoption == PNDCPBlock.IP_ADDRESS:
                print(str(block.parse_ip()))
                parsed["ip"] = s2ip(block.payload[0:4])
            elif blockoption == PNDCPBlock.DEVICE_ID:
                parsed["devId"] = block.payload

            # Padding:
            if block_len % 2 == 1:
                block_len += 1

            # geparsten Block entfernen
            blocks = blocks[block_len + 4:]
            length -= 4 + block_len

        # ret[eth.src] = parsed





        s.close()

