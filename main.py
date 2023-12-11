import argparse


import dcp
import rpc

from util import *
from protocol import *


parser = argparse.ArgumentParser()
parser.add_argument("-i", required=True,
                    help="use INTERFACE", metavar="INTERFACE")
# 请求的操作
parser.add_argument("action", choices=("discover", "get-param", "set-param", "read", "read-inm0-filter", "read-inm0", "read-inm1", "write-inm1"))
# 目标PIC 的MAC地址
parser.add_argument("target", nargs='?', help="MAC address of the device")
# 要读或者写的参数
parser.add_argument("param",  nargs='?', help="parameter to read/write")
# 要写的值
parser.add_argument("value",  nargs='?', help="value to write")
parser.add_argument("additional1",  nargs='?', help="additional parameters")
parser.add_argument("additional2",  nargs='?', help="additional parameters")

args = parser.parse_args()

# ethertype 的值是3，对应ARP协议
s = ethernet_socket(args.i, 3) # 通过网卡名和ICMP协议获取socket
src = get_mac(args.i) # 获取网卡的MAC地址

if args.action == "discover":
    # 发现周围的PLC
    dcp.send_discover(s, src) #从网卡利用socket发出发现报文
    dcp.read_response(s, src, debug=True) #读取响应
elif args.action == "get-param":
    # 从目标机器获取参数
    dcp.get_param(s, src, args.target, args.param)
elif args.action == "set-param":
    # 向目标机器写入参数
    dcp.set_param(s, src, args.target, args.param, args.value)
elif args.action.startswith("read") or args.action.startswith("write"):
    print("Getting station info ...")
    # 获取站点信息
    info = rpc.get_station_info(s, src, args.target)
    # Remote Procedure Call 建立远程过程调用（实际是实现与目标机器的继续通信）
    con = rpc.RPCCon(info)

    print("Connecting to device ...")
    con.connect(src) # 使用RPCCon对象进行连接
    
    if args.action == "read":
        #利用 RPCCon对象 读取 对应api（Application Process Identifier）-slot-subslot-index 的值,最后打印出有效负载
        print(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=int(args.additional2, 16)).payload)
        
    if args.action[5:] == "inm0-filter":
        # 获取设备的 Identification of Manufacturer 0 filter data ，之后遍历，获得该设备的capability
        data = con.read_inm0filter()
        for api in data.keys():
            for slot_number, (module_ident_number, subslots) in data[api].items():
                print("Slot %d has module 0x%04X" % (slot_number, module_ident_number))
                for subslot_number, submodule_ident_number in subslots.items():
                    print("  Subslot %d has submodule 0x%04X" % (subslot_number, submodule_ident_number))

    elif args.action[5:] == "inm0":
        inm0 = PNInM0(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=PNInM0.IDX).payload)
        print(inm0)

    elif args.action[5:] == "inm1":
        inm1 = PNInM1(con.read(api=int(args.param), slot=int(args.value), subslot=int(args.additional1), idx=PNInM1.IDX).payload)
        print(inm1)

    elif args.action[6:] == "inm1":
        api = int(args.param)
        slot = int(args.value)
        subslot = int(args.additional1)
        inm1 = PNInM1(con.read(api, slot, subslot, PNInM1.IDX).payload)
        inm1 = PNInM1(inm1.block_header, bytes(args.additional2, "utf-8"), inm1.im_tag_location)
        con.write(api, slot, subslot, PNInM1.IDX, inm1)
                        

