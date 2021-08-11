from urllib.request import urlopen
from queue import Queue, Empty
import netifaces
import threading
import select
import socket
import re

########################################## Useless ##########################################
def getPublicIp(Net,Print):
    try:
        data = str(urlopen('http://checkip.dyndns.com/').read())
        # data = '<html><head><title>Current IP Check</title></head><body>Current IP Address: 65.96.168.198</body></html>\r\n'
        if Print:
            print('\n\tYour public ip:  '+re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1))
        if Net:
            nettemp = open('logs//temp//net_scan_temp.txt', 'a')
            nettemp.write('\tYour public ip:  '+re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1))
            nettemp.close()
        else:
            nettemp = open('logs//temp//host_scan_temp.txt', 'a')
            nettemp.write('\tYour public ip:  '+re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1))
            nettemp.close()
    except Exception:
        print('\tUnable to detect public ip-address')

def get_all_ips(Net,Print):
    try:
        alladdresseslist = []
        for ifaceName in netifaces.interfaces():
            addresses = [i['addr'] for i in netifaces.ifaddresses(ifaceName).setdefault(netifaces.AF_INET, [{'addr':'No IP addr'}] )]
            if addresses != ['No IP addr']:
                alladdresseslist.append(addresses)
        if Print:
            print('\tYour local ip:   '+str(alladdresseslist))
        if Net:
            nettemp = open('logs//temp//net_scan_temp.txt', 'a')
            nettemp.write('\n\tYour local ip:   '+str(alladdresseslist))
            nettemp.close()
        else:
            nettemp = open('logs//temp//host_scan_temp.txt', 'a')
            nettemp.write('\n\tYour local ip:   '+str(alladdresseslist))
            nettemp.close()
    except Exception:
        print('\tUnable to detect local ip-address')

def get_ips_final(Net,Print):
    getPublicIp(Net,Print)
    get_all_ips(Net,Print)
########################################## End of Useless ##########################################

########################################## Reserve ##########################################
def get_local_ip():
    def udp_listening_server():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(('', 6666))
        s.setblocking(0)
        while True:
            result = select.select([s],[],[])
            msg, address = result[0][0].recvfrom(1024)
            msg = str(msg, 'UTF-8')
            if msg == 'What is my LAN IP address?':
                break
        queue.put(address)

    queue = Queue()
    thread = threading.Thread(target=udp_listening_server)
    thread.queue = queue
    thread.start()
    s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s2.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    waiting = True
    while waiting:
        s2.sendto(str('What is my LAN IP address?').encode(), ("<broadcast>",6666))
        try:
            address = queue.get(False)
        except Empty:
            pass
        else:
            waiting = False
    return address[0]
########################################## End of Reserve ##########################################

# def getIPAddresses():
#     print('Checking for ip-addresses...')
#     from ctypes import Structure, windll, sizeof
#     from ctypes import POINTER, byref
#     from ctypes import c_ulong, c_uint, c_ubyte, c_char
#     MAX_ADAPTER_DESCRIPTION_LENGTH = 128
#     MAX_ADAPTER_NAME_LENGTH = 256
#     MAX_ADAPTER_ADDRESS_LENGTH = 8
#     class IP_ADDR_STRING(Structure):
#         pass
#     LP_IP_ADDR_STRING = POINTER(IP_ADDR_STRING)
#     IP_ADDR_STRING._fields_ = [
#         ("next", LP_IP_ADDR_STRING),
#         ("ipAddress", c_char * 16),
#         ("ipMask", c_char * 16),
#         ("context", c_ulong)]
#     class IP_ADAPTER_INFO (Structure):
#         pass
#     LP_IP_ADAPTER_INFO = POINTER(IP_ADAPTER_INFO)
#     IP_ADAPTER_INFO._fields_ = [
#         ("next", LP_IP_ADAPTER_INFO),
#         ("comboIndex", c_ulong),
#         ("adapterName", c_char * (MAX_ADAPTER_NAME_LENGTH + 4)),
#         ("description", c_char * (MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
#         ("addressLength", c_uint),
#         ("address", c_ubyte * MAX_ADAPTER_ADDRESS_LENGTH),
#         ("index", c_ulong),
#         ("type", c_uint),
#         ("dhcpEnabled", c_uint),
#         ("currentIpAddress", LP_IP_ADDR_STRING),
#         ("ipAddressList", IP_ADDR_STRING),
#         ("gatewayList", IP_ADDR_STRING),
#         ("dhcpServer", IP_ADDR_STRING),
#         ("haveWins", c_uint),
#         ("primaryWinsServer", IP_ADDR_STRING),
#         ("secondaryWinsServer", IP_ADDR_STRING),
#         ("leaseObtained", c_ulong),
#         ("leaseExpires", c_ulong)]
#     GetAdaptersInfo = windll.iphlpapi.GetAdaptersInfo
#     GetAdaptersInfo.restype = c_ulong
#     GetAdaptersInfo.argtypes = [LP_IP_ADAPTER_INFO, POINTER(c_ulong)]
#     adapterList = (IP_ADAPTER_INFO * 10)()
#     buflen = c_ulong(sizeof(adapterList))
#     rc = GetAdaptersInfo(byref(adapterList[0]), byref(buflen))
#     if rc == 0:
#         for a in adapterList:
#             adNode = a.ipAddressList
#             while True:
#                 ipAddr = adNode.ipAddress
#                 if ipAddr:
#                     yield ipAddr
#                 adNode = adNode.next
#                 if not adNode:
#                     break

# for addr in getIPAddresses():
#         print(addr)