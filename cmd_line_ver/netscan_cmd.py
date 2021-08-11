from argparse import ArgumentParser
from subprocess import Popen, PIPE
from bs4 import BeautifulSoup as bs
from time import time
import threading
import requests
import re
import sys
import os

from get_pub_and_loc_ip import get_ips_final
import os_files
import db_conf

# [!]-  rus symbols are used
# [!!!]-    dont scan non-verify web-hages as net::ERR_CERT_COMMON_NAME_INVALID -->
# [!!!]- cause the error appears in this cases and --> the final results may be incorrect or inaccurate.
# [*]-  check the 263-th line for use in-prog input.
# there are input key and ip-address of scan-target.
# [***]-  check the 493-th line for name of Mac-addr and Vendors folder

pattern_open_port = '\d+\/(tcp|udp)\W+open.*'
#pattern_mac_address = 'MAC Address: ([0-9A-F]{2}[:-.]){5}([0-9A-F]{2}).*'
pattern_mac_address = 'MAC Address:.*'
pattern_os = 'OS details:.*'
pattern_os_CPE = 'OS CPE:.*'
pattern_device_type = 'Device type:.*'
#pattern_uptime = 'since.*20\d{2}'
pattern_uptime = 'Uptime guess:/*'

models = [
    # routers -->
    'TL-WR820N', 'TL-840N', 'TD-W8901N', 'TL-WR841N', 'TL-845N', 'TD-W8961N', 'TL-WR940N', 'TL-WR842N', 'TL-WR741N', 'TL-WR741', #tplink
    'RT-N11', 'RT-N12', 'DSL-N16', 'RT-AC51U', 'RT-AC1200', 'RT-AC53', 'RT-AC52U', 'RT-AC57U', 'RT-N18U', #asus
    'Keenetic Start', 'Keenetic Lite', 'Keenetic 4G', 'Keenetic Omni', 'Keenetic City', 'Keenetic Air', 'Keenetic Lite II', 'Keenetic Giga II', 'Keenetic Ultra II',
    'DIR-615S/A1', 'DIR-615/T4', 'DSL-2740U/RA', 'DIR-620S', 'DSL-2750U', 'DIR-806A/RU', 'DIR-822', 'DIR-815', #d-link
    'RG21S', 'BR-6478AC V3', 'BR-6478ACv2', 'BR-6208AC v2', 'BR-6208AC', 'BR-6228nS v3', 'BR-6428nS v4', 'BR-6428nS V5', #edimax
    # printers -->
    'MP287', 'MP328', 'MX366', 'MX416', #canon
    '6200L', '900WD', '940FW', 'AcuLaser C1600', 'Aculaser M1200', 'AL-M2410', 'CX16NF', 'EPL-6200', 'K100', 'L200', 'L800', 'M1200', 'ME340', 'ME900WD', 'ME960FWD', 'MX14NF', 'Stylus CX5505', #epson
    'C4385', 'D5160', 'LaserJet CP1518ni', 'LaserJet M1120 MFP', 'Officejet 4500-G510h', 'Officejet Pro 8500', 'Photosmart C309g', 'LJ M1319 f', #hp
    'Phaser 3052', 'Phaser 3260', 'Phaser 3330', 'Phaser 3610', 'VersaLink B400', 'VersaLink B600', 'VersaLink B610', 'Phaser 5550', 'Phaser 6510', #xerox
    # web-camera -->
    'DS-I114W', 'DS-I203', 'DS-T200', 'DS-I252', 'DS-T101', 'DS-T100', 'DS-I214W', 'DS-I120', 'DS-I252W', 'DS-I122', #hikvision
    'JTSXJ01CM', 'CMSXJ01C', 'MJSXJ02CM', 'SXJ02ZM', 'CMSXJ16A', #xiaomi
    'NC260', 'NC450', 'NC210', 'NC250', #tp-link
    'DCS-3010', 'DCS-4603', 'DCS-6616', 'DCS-3511', 'DCS-4622', 'DCS-7000L', 'DCS-4602EV', 'DCS-6510', 'DCS-4802E', 'DCS-4802E', 'DCS-6513', 'DCS-7413', 'DCS-2670L', #d-link
    'MD701', 'Link-HR06E', 'XF-1604F-LW-K', #toshiba
    'UPC-G4-PRO', 'UVC-G3-PRO', 'UVC-G3-AF', 'UVC-G3-FLEX', 'UVC-G3-DOME' #ubiquiti
]

def clean_up_string(st):
    return st.rstrip().lstrip().replace('  ', ' ')
def clean_up_logs():
    f80 = open('logs/port_80_out.txt', 'w')
    f80.seek(0)
    f80.close()
    f443 = open('logs/port_443_out.txt', 'w')
    f443.seek(0)
    f443.close()
    fnet = open('logs/netscan-nmap-out-net.txt', 'w')
    fnet.seek(0)
    fnet.close()
    fhost = open('logs/netscan-nmap-out-host.txt', 'w')
    fhost.seek(0)
    fhost.close()

def get_content(url_address, errport, ident):
    global router_check, printer_check, camera_check, finish, model
    router_check = False
    printer_check = False
    camera_check = False
    finish = 0
    try:
        if ident == 0:
            req_get = requests.get(url_address, verify=False)
            if req_get.status_code == 200:
                soup_get = bs(req_get.content, 'html.parser')
        
                title_str = str(soup_get.title)
                title_str= title_str.replace('<title>','')
                title_str= title_str.replace('</title>','')
                #print('\nGET-request --> '+'#'*5+' '+ url_address +' '+'#'*5)
                print('found-title:           {title}'.format(title=title_str))

                spisok = []
                delta = ''
                for symbol in str(soup_get):
                    if symbol == '\n':
                        spisok.append(delta)
                        delta = ''
                    else: delta=delta + symbol
        
                for line in spisok:
                    if line.lower().find('router') != -1: router_check = True
                    elif line.lower().find('роутер') != -1: router_check = True
                    elif line.lower().find('printer') != -1: printer_check = True
                    elif line.lower().find('принтер') != -1: printer_check = True
                    elif line.lower().find('camera') != -1: camera_check = True
                    elif line.lower().find('камера') != -1: camera_check = True
                    for each in models:
                        if str(line).lower().find(each.lower()) != -1:
                            model = each

            if req_get.status_code == 401:
                print("[!]Unauthorized to {port} port !".format(port=errport))

                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                nettemp.write("\n[!]Unauthorized to {port} port !".format(port=errport))
                nettemp.close()

            if not router_check and not printer_check and not camera_check: #an error insurance
                if len(port80_out)!=0:
                    for line in port80_out:
                        if line.lower().find('router') != -1: router_check = True
                        elif line.lower().find('роутер') != -1: router_check = True
                        elif line.lower().find('printer') != -1: printer_check = True
                        elif line.lower().find('принтер') != -1: printer_check = True
                        elif line.lower().find('camera') != -1: camera_check = True
                        elif line.lower().find('камера') != -1: camera_check = True
                if len(port443_out)!=0:
                    for line in port443_out:
                        if line.lower().find('router') != -1: router_check = True
                        elif line.lower().find('роутер') != -1: router_check = True
                        elif line.lower().find('printer') != -1: printer_check = True
                        elif line.lower().find('принтер') != -1: printer_check = True
                        elif line.lower().find('camera') != -1: camera_check = True
                        elif line.lower().find('камера') != -1: camera_check = True

            outforcam = []
            current_path = str(os.getcwd()).replace('netscan_cmd.py','')
            with open('{cur}\\logs\\netscan-nmap-out-host.txt'.format(cur = current_path), 'r') as filehandle:  
                content = filehandle.readlines()
                for line in content:
                    current = line
                    outforcam.append(current) 
            for every in outforcam:
                if (every.lower().find('PLAY')!=0 or every.lower().find('PAUSE')!=0) or (every.lower().find('SETUP')!=0 or every.lower().find('TEARDOWN')!=0):
                    camera_check = True
            finish = 0
            return finish
            
        elif ident == 1:
            port80_logs = err_insurrance('logs\port_80_out.txt')
            if len(port80_logs)!=0:
                for each in port80_logs:
                    if each.lower().find('router') != -1: router_check = True
                    elif each.lower().find('роутер') != -1: router_check = True
                    elif each.lower().find('printer') != -1: printer_check = True
                    elif each.lower().find('принтер') != -1: printer_check = True
                    elif each.lower().find('camera') != -1: camera_check = True
                    elif each.lower().find('камера') != -1: camera_check = True

            port443_logs = err_insurrance('logs\port_443_out.txt')
            if len(port443_logs)!=0:
                for each in port443_logs:
                    if each.lower().find('router') != -1: router_check = True
                    elif each.lower().find('роутер') != -1: router_check = True
                    elif each.lower().find('printer') != -1: printer_check = True
                    elif each.lower().find('принтер') != -1: printer_check = True
                    elif each.lower().find('camera') != -1: camera_check = True
                    elif each.lower().find('камера') != -1: camera_check = True
            return finish

    except ConnectionError:
        print("[!]Can't establish the connection to {port} port!".format(port=errport))
        finish = 1

        nettemp = open('logs//temp//host_scan_temp.txt', 'a')
        nettemp.write("\n[!]Can't establish the connection to {port} port!".format(port=errport))
        nettemp.close()
        
        return finish
    except:
        print('[!]An Error occurance in web-scan {port} port! (probably cause sites\' security)'.format(port=errport))
        finish = 1

        nettemp = open('logs//temp//host_scan_temp.txt', 'a')
        nettemp.write('\n[!]An Error occurance in web-scan {port} port! (probably cause sites\' security)'.format(port=errport))
        nettemp.close()
        
        return finish

def run_nmap_scan_list(ip_address):
    nettemp = open('logs//temp//net_scan_temp.txt', 'a')
    print('\nScan process for network {ip_address} started...'.format(ip_address=ip_address))
    nettemp.write('[*] Scan process for network {ip_address} started...\n\n'.format(ip_address=ip_address))

    nmap_process = Popen(['nmap.exe','-sn','-v','-oN','logs/netscan-nmap-out-net.txt',ip_address], stdout=PIPE, stderr=PIPE)
    start_time  = time()

    while True:
        output_line = nmap_process.stdout.readline()
        if output_line:
            output_line = output_line.decode()
            f_out = str(output_line).lower()
            if f_out.find('host down')==-1:
                if f_out.find('nmap scan report for ')!=-1:
                    print('')
                    print(f_out.strip())
                    nettemp.write('\n'+f_out.strip()+'\n')
                else:
                    print(f_out.strip())
                    nettemp.write(f_out.strip()+'\n')
        else:
            break
    
    stop_time = time() - start_time
    sec, milsec = str(stop_time).split('.')
    sec+='.'+milsec[0]+milsec[1]+milsec[2]

    print('\n[*] Process for {ip_address} done! Elapsed time: {elapsed_time}'.format(ip_address=ip_address, elapsed_time=sec))
    nettemp.write('\n[*] Process for {ip_address} done! Elapsed time: {elapsed_time}\n\n'.format(ip_address=ip_address, elapsed_time=sec))
    nettemp.close()


def run_nmap_scan(ip_address):
    
    global host_info, lports, lservices, model
    global service_OS, service_CPE, aggr_OS, mac_address
    model = ''
    mac_address = ''
    service_OS = ''
    service_CPE = ''
    aggr_OS = ''
    lports = []
    lservices = []
    host_info = {
        # 'ip-address': ip_address,
        'mac-address': None,
        'operating-system': None,
        'os-cpe': None, 
        'device-type': None,
        'uptime': None,
        'open-ports': []
    }

    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
    nettemp.write('\n\n\tSCAN REPORT FOR {addr}\n'.format(addr = ip_address))

    print('\n[*] NMAP process for {ip_address} started...'.format(ip_address=ip_address))
    nettemp.write('\n[*] NMAP process for {ip_address} started...'.format(ip_address=ip_address))
    start_time  = time()

    global port80_out, port443_out #additional variables for testing
    port80_out  = []
    port443_out = []
    port80_check = False
    port443_check = False
    nmap_process = Popen(['nmap.exe','-O','-A','-v','-oN','logs/netscan-nmap-out-host.txt',ip_address], stdout=PIPE, stderr=PIPE)

    while True:
        output_line = nmap_process.stdout.readline()

        if output_line:
            output_line = output_line.decode()
            
            for each in models:
                if str(output_line).lower().find(each.lower()) != -1:
                    model = each

            if re.match(pattern_mac_address, output_line):
                print('\t', 'Discovered MAC address')
                nettemp.write('\n\tDiscovered MAC address')

                regex_mac_address = re.search('([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', output_line, re.I) #out --> Match
                if regex_mac_address:
                    mac_address = regex_mac_address.group()
                    host_info['mac-address'] = mac_address

            elif re.match(pattern_os, output_line):
                print('\t', 'Discovered the most probable OS')
                nettemp.write('\n\tDiscovered the most probable OS')

                os = re.split(':', output_line)[1]
                if os:
                    os = os.strip()
                    host_info['operating-system'] = os

            elif re.match(pattern_os_CPE, output_line):
                print('\t', 'Discovered OS-CPE')
                nettemp.write('\n\tDiscovered OS-CPE')

                os_cpe = re.split('CPE:', output_line)[1]
                if os_cpe:
                    os_cpe = os_cpe.strip()
                    host_info['os-cpe'] = os_cpe

            elif re.match(pattern_device_type, output_line):
                print('\t', 'Discovered the most probable device type')
                nettemp.write('\n\tDiscovered the most probable device type')

                device_type = re.split(':', output_line)[1]
                if device_type:
                    device_type = device_type.strip()
                    host_info['device-type'] = device_type

            elif re.match(pattern_uptime, output_line):
                print('\t','Discovered the uptime')
                nettemp.write('\n\tDiscovered the uptime')
                uptime = re.split('guess: ', output_line)[1]
                if uptime:
                    uptime = uptime.strip()
                    host_info['uptime'] = uptime

            elif re.match(pattern_open_port, output_line):
                print('\t', 'Discovered open port')
                nettemp.write('\n\tDiscovered open port')

                if (port80_check or port443_check) and (str(output_line)).find('|')==-1:
                    port80_check  = False
                    port443_check = False

                port_and_protocol_string, service_and_description_string = re.split('open', output_line)

                port, protocol = re.split('\/', port_and_protocol_string)
                if port.strip() == str(80): port80_check  = True
                if port.strip() != str(80): port80_check  = False
                if port.strip() == str(443): port443_check = True
                if port.strip() != str(443): port443_check = False

                service_and_description_list = re.split(' ', clean_up_string(service_and_description_string))
                service_and_description_list = [element for element in service_and_description_list if element != '']
                service, description = service_and_description_list[0], ' '.join(service_and_description_list[1:]) \
                    if service_and_description_list[1:] else None

                protocol = protocol.strip()
                if service:
                    service = service.strip()
                if description:
                    description = description.strip()
                
                lports.append(int(port))
                lservices.append(service)
                host_info['open-ports'].append(
                    '{port}/{protocol} {service} {description}'.format(
                        port=port, protocol=protocol, service=service, description=description
                    )
                )

            elif re.match('Service Info: ',output_line):
                outstr = output_line[14:]
                if outstr.find(';')!=-1:
                    outstr = outstr.replace('OS: ','')
                    outstr = outstr.replace(' CPE: ','').split(';')
                    service_OS  = outstr[0].strip()
                    service_CPE = outstr[1].strip()
                elif outstr.find('OS:')!=-1:
                    outstr = outstr.replace('OS: ','')
                    service_OS = outstr.strip()
                    service_CPE = ''
                else:
                    outstr = outstr.replace('CPE: ','')
                    service_CPE = outstr.strip()
                    service_OS = ''

            elif re.match('Aggressive OS guesses: ',output_line):
                aggr_OS = output_line[24:]

            if port80_check:
                port80_out.append(str(output_line))
            if port443_check:
                port443_out.append(str(output_line))
            # if (str(output_line)).find('|')==-1:
            #     port80_check  = False
            #     port443_check = False

        else:
            break

    global stop_time 
    stop_time = time() - start_time
    sec, milsec = str(stop_time).split('.')
    sec+='.'+milsec[0]+milsec[1]+milsec[2]

    print('\n[***] NMAP process for {ip_address} done! Elapsed time: {elapsed_time}'.format(
        ip_address=ip_address, elapsed_time=sec)
    )
    nettemp.write('\n[***] NMAP process for {ip_address} done! Elapsed time: {elapsed_time}'.format(ip_address=ip_address, elapsed_time=sec))
    nettemp.close()

    return host_info

def func_scan():
    try:
        global ip, key
        key = 0
        print('\n\t     Welcome to NetScan_cmd application, {user}.\n'.format(user = str(os.getlogin())))
        get_ips_final(True, True)
        print('\nType ipv4 of network (x.x.x.x/24) or host. to start analyzing.')
        ip = str(input('Input ipv4 is:    '))

        if ip.__len__()>18 or ip.__len__()<7 or ip.count('.')!=3:
            print('[!]You should input a correct IP-address, nothing else.')
            sys.exit(0)

        if ip and key == 0:
            if str(ip).find('/24') != -1 or str(ip).find('\\24') != -1:
                open('logs//temp//net_scan_temp.txt', 'w').close()
                if str(ip).find('\\24') != -1:
                    ip = str(ip).replace('\\','/')
                    run_nmap_scan_list(ip)
                else:
                    run_nmap_scan_list(ip)

                get_ips_final(True, True)
                validip = str(ip).replace('/','(')
                validip = str(validip).replace('\\','(')
                validip+=')'
                os_files.rename_static(True, validip)

                print('\n[?]Do u wanna to spot scanning ?')
                quest = str(input('[y/n]     '))
                if quest.lower() == 'y' or quest.lower() == 'н':
                    key = 1
                elif quest.lower()=='n' or quest.lower()=='т': key==0
                else: 
                    if quest.lower()!='n' or quest.lower()!='т': print('\nYou should type Y or N symbols (lowers also included).')
                    sys.exit(0)
            else: key = 2

        if ip and key!=0:
            open('logs//temp//host_scan_temp.txt', 'w').close()
            nettemp = open('logs//temp//host_scan_temp.txt', 'a')
            nettemp.write('\n')

            if key == 1:
                get_ips_final(False, False)
                new_ip = input('\nIP-address for scanning is:    ')
                ip = new_ip
                run_nmap_scan(new_ip)
                # os_files.rename_static(False, new_ip)

            elif key == 2:
                get_ips_final(False, True)
                run_nmap_scan(ip)

            if host_info['open-ports'].__len__() == 0:
                host_info['open-ports'].append('None')
            if host_info['operating-system'] == None:
                if service_OS != '':
                    host_info['operating-system'] = service_OS
                else: host_info['operating-system'] = 'not defined'
            if host_info['os-cpe'] == None:
                if aggr_OS != '':
                    host_info['os-cpe'] = aggr_OS
                elif service_CPE != '':
                    host_info['os-cpe'] = service_CPE
                else: host_info['os-cpe'] = 'not defined'
            for key, value in host_info.items():
                if hasattr(value, 'append'):
                    print('{key}:'.format(key=key))
                    nettemp.write('\n{key}:'.format(key=key))
                    for v in value:
                        print('\t{v}'.format(v=v))
                        nettemp.write('\n\t{v}'.format(v=v))
                else:
                    print('{key}: {value}'.format(key=key, value=value))
                    nettemp.write('\n{key}: {value}'.format(key=key, value=value))
            nettemp.close()

            thr_write = threading.Thread(name='Writing txt',target=somefunc)
            thr_write.start()
            thr_DevT_byS = threading.Thread(name='DT det by services',target=DevT_http_https)
            thr_DevT_byS.start()
            thr_DevT_byS.join()
            thr_DevT_byP = threading.Thread(name='DT det by ports',target=DevT_byPorts)
            thr_DevT_byP.start()
            thr_DevT_byP.join()

            os_files.web_impl()
            os_files.rename_static(False, ip)
            
        compare = str(input('\nCompare data from logging directories? (compare of logs\' data between same hosts) [y\\n]  '))
        if compare.lower() == 'y' or compare.lower() == 'н': db_conf.compare_res()

        update = str(input('\nUpdate data base of valid outputs? (or exit) [y\\n]  '))
        if update.lower() == 'y' or update.lower() == 'н': 
            db_conf.update()
            sys.exit(0)
        else: sys.exit(0)

    except SystemExit:
        print('\n\t    Designed and implemented by Subaev RN.')   
        print('\t        Press Enter to end the app...\n')
        input()
    except Exception:
        print('\n[!]Aborted as something went wrong ... Check possibility of using nmap.')
        print('\n\t    Designed and implemented by Subaev RN.')   
        print('\t        Press Enter to end the app...\n')
        input()

def somefunc():
    if len(port80_out)!=0:
        f = open('logs/port_80_out.txt', 'w')
        for index in port80_out:
            f.write(index)
        f.close()
    if len(port443_out)!=0:
        f = open('logs/port_443_out.txt', 'w')
        for index in port443_out:
            f.write(index)
        f.close()

def DevT_http_https():
    print('\n[#] Detailed analysis:')
    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
    nettemp.write('\n\n[#] Detailed analysis:')
    nettemp.close()

    detailed = {
        'device-type::80  --> ': None,
        'device-type::443 --> ': None
    }

    if lports.__contains__(80):
        finish_f = get_content('http://{ip_address}:80'.format(ip_address=ip),80,0)
        if finish_f==1: get_content('http://{ip_address}:80'.format(ip_address=ip),80,1)
        if router_check: detailed['device-type::80  --> '] = 'router'
        elif printer_check: detailed['device-type::80  --> '] = 'printer'
        elif camera_check: detailed['device-type::80  --> '] = 'camera'
    if lports.__contains__(443):
        finish_f = get_content('https://{ip_address}:443'.format(ip_address=ip),443,0)
        if finish_f==1: get_content('http://{ip_address}:443'.format(ip_address=ip),80,1)
        if router_check: detailed['device-type::443 --> '] = 'router'
        elif printer_check: detailed['device-type::443 --> '] = 'printer'
        elif camera_check: detailed['device-type::443 --> '] = 'camera'

    

    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
    for key, value in detailed.items():
        i = 0
        if value == None and i == 0 and not lports.__contains__(80):
            value = 'port doesn\'t exist'
            i= i+1
        elif value == None and i == 1 and not lports.__contains__(443):
            value = 'port doesn\'t exist'
        elif i==0 and not router_check and not printer_check and not camera_check: 
            value = 'not found'
            i= i+1
        elif i==1 and not router_check and not printer_check and not camera_check: 
            value = 'not found'

        print('{key}: {value}'.format(key=key, value=value))
        nettemp.write('\n{key}: {value}'.format(key=key, value=value))

    nettemp.close()

def DevT_byPorts():
    global web_camera_perc, pc_perc, server_perc, mobile_perc, printer_perc, router_perc, mac_address
    com = ''
    signatures = []
    web = []
    connect = []
    private = []
    others = []
    web_camera_perc =  0
    pc_perc = 0
    server_perc = 0
    mobile_perc = 0
    printer_perc = 0
    router_perc = 0

    #All most common and often ports for devices are -->
    web_camera_idnt = [554, 80, 443] #554
    pc_idnt         = [135, 139, 445, 554, 1084, 5357] #139    plus all 21-25 ports there + 80 and e.t.c. [??]
    server_idnt     = [3389, 259, 80, 8888, 443, 465, 587, 445, 3268,
                       21, 22, 23, 25, 587, 143, 53, 500, 873, 8443] #80+443 +465+ 445+3268 \+/ 21-25+.. 
    mobile_idnt     = [62078, 49152, 49163] #62078
    printer_idnt    = [631, 515] #631
    router_idnt     = [22, 23, 53, 80, 443, 445, 137] #80, 443 \+/ 22-23

    #WebCam -->
    if lports.__contains__(554) and not lports.__contains__(135) and not lports.__contains__(137) and not lports.__contains__(139):
        web_camera_perc = 55
        if lports.__len__()<5: web_camera_perc+=12
        if lports.__contains__(554): web_camera_perc+=14
        if camera_check: web_camera_perc=web_camera_perc+30
        if lports.__contains__(322): web_camera_perc += 10
        if web_camera_perc > 100: web_camera_perc = 100
    if len(lports) <= 2 and (lports.__contains__(80) or lports.__contains__(8080) and web_camera_perc == 0):
        web_camera_perc = 50
        if camera_check: web_camera_perc += 23
        if web_camera_perc > 100: web_camera_perc = 100
    #Printer -->
    if lports.__contains__(631) or lports.__contains__(515) and web_camera_perc!=100:
        printer_perc = 65
        if printer_check: printer_perc=printer_perc+35
        if printer_perc != 100:
            if len(lports) >= 5: printer_perc -= 53
    #Phone -->
    if lports.__contains__(62078) and not lports.__contains__(135) and not lports.__contains__(137) and not lports.__contains__(139) and web_camera_perc!=100 and printer_perc!=100:
        mobile_perc = 100
        com = 'Device is using the signature 62078 port <-> UPnP/Bonjour, Apple'
    if len(lports)<=3 and lports.__contains__(49152) and lports.__contains__(49163):
        mobile_perc = 90
        com = 'Device is using signature 49152 and 49163-only ports <--> probably IPhone'
    if len(lports)!=0 and web_camera_perc!=100 and printer_perc!=100 and mobile_perc!=100:
        #Router -->
        if (lports.__contains__(80) or lports.__contains__(443) or lports.__contains__(8080)):
            router_perc = 50
            if not (lports.__contains__(139) or lports.__contains__(135)) and len(lports)<=5:
                if router_check: router_perc = 99
            if (lports.__contains__(22) or lports.__contains__(23)) and router_perc!=100:
                router_perc += 22
            if lports.__contains__(53): router_perc +=15
            if lports.__contains__(1900): router_perc +=15
            if router_check: router_perc += 25
        if router_perc > 100: router_perc = 100
        #Server -->
        if len(lports)<4 and (lports.__contains__(80) or lports.__contains__(443)) and router_perc!=100:
            server_perc = 100
            router_perc = 0
        if ((lports.__contains__(80) or lports.__contains__(443) or lports.__contains__(8080)) and server_perc!=100 and router_perc!=100):
            if not lports.__contains__(135) and not lports.__contains__(139) and not lports.__contains__(5357):
                server_perc = 70
                for port in lports:
                    if port == 21:   server_perc=server_perc+3
                    elif port == 465:  server_perc=server_perc+5
                    elif port == 556:  server_perc=server_perc+10
                    elif port == 53:   server_perc=server_perc+10
                    elif port == 110 or port == 109 or port == 995:  server_perc=server_perc+7
                    elif port == 143:  server_perc=server_perc+5
                    elif port == 3268 or port == 3269: server_perc=server_perc+8
                    elif port == 3389: server_perc=server_perc+10
                    elif port >= 3306 and port <= 3309: server_perc=server_perc+2
                    elif port == 1186 or port == 7306 or port == 7307: server_perc=server_perc+2
                    elif port == 1433 or port == 1434: server_perc=server_perc+2
                    elif port == 593: server_perc=server_perc+2
                    elif port == 445: server_perc=server_perc+7
                    elif port == 88 or port == 464: server_perc=server_perc+7
                    elif port == 25 or port == 587: server_perc=server_perc+3
                    elif port == 110: server_perc=server_perc+3
                    elif port == 143: server_perc=server_perc+3
                    elif port == 119: server_perc=server_perc+3
                    elif port == 400 or port == 1156 or port == 1157 or port == 1158 or port == 1159 or port == 1526 or port == 2030 or port == 2483 or port == 2484 or port == 3872: server_perc=server_perc+2
                    elif port == 5432: server_perc=server_perc+5
                    elif port == 50000 or port == 523: server_perc=server_perc+3
                if server_perc > 100: server_perc=100
        #PC -->
        if server_perc!=100 and router_perc!=100:
            pc_perc = 75
            for port in lports:
                if port == 445:   pc_perc=pc_perc+10
                elif port == 554:   pc_perc=pc_perc+5
                elif port == 1084:  pc_perc=pc_perc+5
                elif port >= 49152: pc_perc=pc_perc+7
            if not lports.__contains__(80) and not lports.__contains__(8008) and not lports.__contains__(443) and not lports.__contains__(8080) and not lports.__contains__(81) and not lports.__contains__(8081):
                pc_perc+=15
            if pc_perc > 100: pc_perc=100

    #output the results -->
    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
    detail_out = { 'Final device-type': [],
                   'Final vendor': None     }

    if mobile_perc>0: detail_out['Final device-type'].append('Mobile phone ({percent}%)'.format(percent=mobile_perc))
    if web_camera_perc>0: detail_out['Final device-type'].append('Web camera ({percent}%)'.format(percent=web_camera_perc))
    if printer_perc>0: detail_out['Final device-type'].append('Printer ({percent}%)'.format(percent=printer_perc))
    if router_perc>0: detail_out['Final device-type'].append('Router ({percent}%)'.format(percent=router_perc))
    if server_perc>0: detail_out['Final device-type'].append('Server ({percent}%)'.format(percent=server_perc))
    if pc_perc>0: detail_out['Final device-type'].append('PC ({percent}%)'.format(percent=pc_perc))
    
    if com!='': 
        print(com)
        nettemp.write('\n'+com+'\n')

    else:
        for port in lports:
            if port == 135 or port == 137 or port == 139: signatures.append(str(port)+'- msrpc')
            elif port >= 137 and port <= 139: signatures.append(str(port)+'- netbios_prot')
            elif port == 554: signatures.append(str(port)+'- rtsp')
            elif port == 631: signatures.append(str(port)+'- ipp')
            elif port == 3268: signatures.append(str(port)+'- g.catalog')
            elif port == 3269: signatures.append(str(port)+'- g.catalog.ssh')
            elif port == 3389: signatures.append(str(port)+'- rdp')
            elif port == 80 or port == 81: web.append(str(port)+'- http')
            elif port == 443: web.append(str(port)+'- https')
            elif port == 8008 or port == 8080 or port == 8081 or port == 8090: web.append(str(port)+'- http_alt')
            elif port == 21: connect.append(str(port)+'- ftp')
            elif port == 23: connect.append(str(port)+'- tftp')
            elif port == 22: connect.append(str(port)+'- ssh')
            elif port == 23: connect.append(str(port)+'- telnet')
            elif port == 53: connect.append(str(port)+'- dns')
            elif port >= 49152: private.append(str(port))
            elif port != 62078 and port != 554 and port != 631:
                if port == 143: others.append(str(port)+'- imap')
                elif port == 556: others.append(str(port)+'- remotefs')
                elif port == 8000: others.append(str(port)+'- irdmi')
                elif port >= 3306 and port <= 3309: others.append(str(port)+'- mysql')
                elif port == 1186 or port == 7306 or port == 7307: others.append(str(port)+'- mysql')
                elif port == 1433 or port == 1434: others.append(str(port)+'- Mic.sql.server')
                elif port == 593: others.append(str(port)+'- rpc.http')
                elif port == 445: others.append(str(port)+'- Mic.-ds')
                elif port == 88 or port == 464: others.append(str(port)+'- kerberos')
                elif port == 25 or port == 587: others.append(str(port)+'- smtp')
                elif port == 110: others.append(str(port)+'- pop3')
                elif port == 143: others.append(str(port)+'- imap')
                elif port == 119: others.append(str(port)+'- nntp')
                elif port == 400 or port == 1156 or port == 1157 or port == 1158 or port == 1159 or port == 1526 or port == 2030 or port == 2483 or port == 2484 or port == 3872: others.append(str(port)+'- oracle')
                elif port == 5432: others.append(str(port)+'- postgresql')
                elif port == 27017: others.append(str(port)+'- mongodb')
                elif port == 50000 or port == 523: others.append(str(port)+'- DB2')
                else: others.append(str(port))

    if len(signatures)!=0: 
        print('signature ports:     {l}'.format(l=signatures))
        nettemp.write('\nsignature ports:     {l}'.format(l=signatures))
    if len(connect)!=0: 
        print('connect&fs ports:    {l}'.format(l=connect))
        nettemp.write('\nconnect&fs ports:    {l}'.format(l=connect))
    if len(web)!=0: 
        print('web ports:           {l}'.format(l=web))
        nettemp.write('\nweb ports:           {l}'.format(l=web))
    if len(private)!=0: 
        print('private-using ports: {l}'.format(l=private))
        nettemp.write('\nprivate-using ports: {l}'.format(l=private))
    if len(others)!=0: 
        print('service ports:       {l}'.format(l=others))
        nettemp.write('\nservice ports:       {l}\n'.format(l=others))

#Mac detection-->
    folder_name = 'vendors/'
    mac_cisco = txt_func('{folder}cisco.txt'.format(folder=folder_name))
    mac_tplink = txt_func('{folder}tplink.txt'.format(folder=folder_name))
    mac_hp = txt_func('{folder}hp.txt'.format(folder=folder_name))
    mac_intel = txt_func('{folder}intel.txt'.format(folder=folder_name))
    mac_huawei = txt_func('{folder}huawei.txt'.format(folder=folder_name))
    mac_samsung = txt_func('{folder}samsung.txt'.format(folder=folder_name))
    mac_nokia = txt_func('{folder}nokia.txt'.format(folder=folder_name))
    mac_dell = txt_func('{folder}dell.txt'.format(folder=folder_name))
    mac_xiaomi = txt_func('{folder}xiaomi.txt'.format(folder=folder_name))
    mac_asus = txt_func('{folder}asus.txt'.format(folder=folder_name))
    mac_d_link = txt_func('{folder}d_link.txt'.format(folder=folder_name))
    mac_microsoft = txt_func('{folder}microsoft.txt'.format(folder=folder_name))
    mac_liteon = txt_func('{folder}liteon.txt'.format(folder=folder_name))
    mac_hewpacent = txt_func('{folder}hewpacent.txt'.format(folder=folder_name))
    mac_xerox = txt_func('{folder}xerox.txt'.format(folder=folder_name))
    mac_edimax = txt_func('{folder}edimax.txt'.format(folder=folder_name))
    mac_ubiquinty = txt_func('{folder}ubiqunti.txt'.format(folder=folder_name))
    mac_zyxel = txt_func('{folder}zyxel.txt'.format(folder=folder_name))
    mac_apple = txt_func('{folder}apple.txt'.format(folder=folder_name))
    mac_panasonic = txt_func('{folder}panasonic.txt'.format(folder=folder_name))
    mac_philips = txt_func('{folder}philips.txt'.format(folder=folder_name))
    mac_toshiba = txt_func('{folder}toshiba.txt'.format(folder=folder_name))
    mac_epson = txt_func('{folder}epson.txt'.format(folder=folder_name))
    mac_canon = txt_func('{folder}canon.txt'.format(folder=folder_name))
    mac_hikvision = txt_func('{folder}hikvision.txt'.format(folder=folder_name))
    vendor = [
        mac_cisco, mac_d_link, mac_epson, mac_canon,
        mac_tplink, mac_microsoft, mac_hp, 
        mac_intel, mac_huawei, mac_samsung,
        mac_nokia, mac_dell, mac_xiaomi,
        mac_asus, mac_liteon, mac_hewpacent,
        mac_xerox, mac_edimax, mac_ubiquinty,
        mac_zyxel, mac_apple, mac_panasonic,
        mac_philips, mac_toshiba, mac_hikvision
    ]
    vendor_name = [
        'Cisco', 'D-Link', 'Epson', 'Canon',
        'TPlink', 'Microsoft', 'HP', 
        'mac_intel', 'Huawei', 'Samsung',
        'Nokia', 'Dell', 'Xiaomi',
        'Asus', 'Liteon', 'Hewpacent',
        'Xerox', 'Edimax', 'Ubiquinty',
        'Zyxel', 'Apple', 'Panasonic',
        'Philips', 'Toshiba', 'Hikvision'
    ]

    if mac_address == '': detail_out['Final vendor'] = '     Mac wasn\'t found'
    elif mac_address.find('00:12:16')!=0 or mac_address.find('00.12.16')!=0 or mac_address.find('00-12-16')!=0:
        detail_out['Final vendor'] = '     Icp Internet Communication Payment AG'
    else:
        name_id = -1
        if len(mac_address) == 17: mac_address = mac_address[:-9]
        if len(mac_address) == 14: mac_address = mac_address[:-7]
        for vend in vendor:
            name_id+=1
            for addr in vend:
                if mac_address == addr: detail_out['Final vendor'] = '     {name}'.format(name=vendor_name[name_id])

    if detail_out['Final vendor'] == '': detail_out['Final vendor'] = '     Vendor wasn\'t found'

    # final out -->
    print('')

    for key, value in detail_out.items():
        print('{key}:   {value}'.format(key=key, value=value))
        nettemp.write('\n')
        nettemp.write('{key}:   {value}'.format(key=key, value=value))

    if model != '':
        print('Final model:         {model}'.format(model=model))
        nettemp.write('\nFinal model:         {model}'.format(model=model))
    else:
        print('Final model:         no match found')
        nettemp.write('\nFinal model:         no match found')

    nettemp.close()

def txt_func(filepath):
    out = []
    with open(filepath, 'r') as filehandle:  
        content = filehandle.readlines()

        for line in content:
            current = line[:-1]
            current = current.split('\t')
            for i in current:
                i=i.replace(':xx:xx:xx','')
                i=i.replace('-xx-xx-xx','')
                i=i.replace('xx.xxxx','')
                out.append(i)
        out[len(out)-1] = out[len(out)-1].replace(':xx:xx:x','')
        out[len(out)-1] = out[len(out)-1].replace('-xx-xx-x','')
        out[len(out)-1] = out[len(out)-1].replace('xx.xxx','')
    return(out)

def err_insurrance(filepath):
    out = []
    with open(filepath, 'r') as filehandle:  
        content = filehandle.readlines()

        for line in content:
            current = line[:-1]
            out.append(current)
    return(out)

if __name__ == '__main__':
    try:
        clean_up_logs()
        func_scan()

    except KeyboardInterrupt:
        print('\n\n[!]Aborted by user !')
        sys.exit(-1)