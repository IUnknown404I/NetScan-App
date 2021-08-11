import os
import sys
import shutil

# def dir(check_names):
def dir(extrapath):
    current_path = str(os.getcwd()).replace('os_files.py','')
    current_path+=extrapath
    # print(sys.modules[__name__])
    dirpath = list(os.listdir(path=current_path))

    return dirpath
    # for every in dirpath:
    #     pass

def del_file(path):
    try:
        if os.path.isfile(path):
            os.remove(path)
        else:
            # print("Error: %s file not found" % path)
            pass
    except OSError as e:
        # print ("Error: %s - %s." % (e.filename, e.strerror))
        pass

def copy_file(filename):
    current_path = str(os.getcwd()).replace('os_files.py','')
    shutil.copy("{cur}\\logs\\temp\\{p}".format(cur = current_path, p = filename), "{cur}\\logs\\hosts".format(cur = current_path))

    # del_path = current_path+'\\logs\\temp\\'+filename
    # del_file(del_path)

def rename_static(Net,ip):   
    try: 
        current_path = str(os.getcwd()).replace('os_files.py','')
        if Net:
            del_file('{cur}\\logs\\temp\\net_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
            os.rename("{cur}\\logs\\temp\\net_scan_temp.txt".format(cur = current_path),'{cur}\\logs\\temp\\net_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
        else:   
            del_file('{cur}\\logs\\temp\\host_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = str(ip)))
            os.rename("{cur}\\logs\\temp\\host_scan_temp.txt".format(cur = current_path),'{cur}\\logs\\temp\\host_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = str(ip)))
    except Exception:
        pass

def web_impl():
    current_path = str(os.getcwd()).replace('os_files.py','')
    
    out80 = []
    with open('{cur}\\logs\\port_80_out.txt'.format(cur = current_path), 'r') as filehandle:  
        content = filehandle.readlines()

        for line in content:
            current = line[:-1]
            out80.append(current)

    out443 = []
    with open('{cur}\\logs\\port_443_out.txt'.format(cur = current_path), 'r') as filehandle:  
        content = filehandle.readlines()

        for line in content:
            current = line[:-1]
            out443.append(current)

    if out80.__len__()>0 or out443.__len__()>0:
        nettemp = open('{cur}//logs//temp//host_scan_temp.txt'.format(cur = current_path), 'a')
        nettemp.write('\n\n\n\tWeb-Out-s:\n')
        nettemp.close()

    if out80.__len__()>0:
        nettemp = open('{cur}//logs//temp//host_scan_temp.txt'.format(cur = current_path), 'a')
        nettemp.write('\t80 Port\n\n')
        for lines in out80:
            nettemp.write(lines+'\n')
        nettemp.close()

    if out443.__len__()>0:
        nettemp = open('{cur}//logs//temp//host_scan_temp.txt'.format(cur = current_path), 'a')
        nettemp.write('\t443 Port\n\n')
        for lines in out443:
            nettemp.write(lines+'\n')
        nettemp.close()