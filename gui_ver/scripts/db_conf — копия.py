import os
import os_files

def update():
    tempdir = os_files.dir('\\logs\\temp')
    hostsdir = os_files.dir('\\logs\\hosts')
    current_path = str(os.getcwd()).replace('db_conf.py','')

    if tempdir.__len__()>0:
        for every in tempdir:
            if hostsdir.count(every)==0:
                outtemp1 = []

                with open('{cur}\\logs\\temp\\{ev}'.format(cur = current_path, ev = every), 'r') as filehandle:  
                    content = filehandle.readlines()
                    for line in content:
                        current = line[:-1]
                        outtemp1.append(current)

                if outtemp1.__len__()>0: os_files.copy_file(every)
            else:
                outtemp2 = []
                with open('{cur}\\logs\\temp\\{ev}'.format(cur = current_path, ev = every), 'r') as filehandle:  
                    content = filehandle.readlines()
                    for line in content:
                        current = line[:-1]
                        outtemp2.append(current)

                every_host = hostsdir[hostsdir.index(every)]
                outhost = []
                with open('{cur}\\logs\\hosts\\{ev_host}'.format(cur = current_path, ev_host = every_host), 'r') as filehandle:  
                    content = filehandle.readlines()
                    for line in content:
                        current = line[:-1]
                        outhost.append(current)

                if outtemp2.__len__()>0:
                    if outhost.__len__()>0: 
                        delpath = current_path+'\\logs\\hosts\\'+str(every)
                        os_files.del_file(delpath)
                        os_files.copy_file(every)
                    else:
                        delpath = current_path+'\\logs\\hosts\\'+str(every)
                        os_files.del_file(delpath)
                        os_files.copy_file(every)
        print('[*]Successfully updated!')
    else: print('[!]Temp-directory is empty')


def compare_res():
    comp_out = []
    err_list = []
    len_check = False
    tempdir = os_files.dir('\\logs\\temp')
    hostsdir = os_files.dir('\\logs\\hosts')
    current_path = str(os.getcwd()).replace('db_conf.py','')
    print('\n\tComparing data from \\Temp\\ dir to \\Hosts\\ dir.\n')

    if tempdir.__len__()>0:
        for temp in tempdir:
            err_list.append('The line numbering is based on a largest log.\n')

            if hostsdir.count(temp)==0:
                print('[#]Log {ev}  from \\Temp\\ is unique. No match found in \\Hosts\\.\n'.format(ev = temp))
                comp_out.append('[*]Log:  {ev}  is unique. No match found in \\Hosts\\.\n'.format(ev = temp))

            else:
                tempout = []
                with open('{cur}\\logs\\temp\\{temp}'.format(cur = current_path, temp = temp), 'r') as filehandle:  
                    content = filehandle.readlines()
                    for line in content:
                        current = line
                        tempout.append(current)
                host = hostsdir[hostsdir.index(temp)]
                hostout = []
                with open('{cur}\\logs\\hosts\\{host}'.format(cur = current_path, host = host), 'r') as filehandle:  
                    content = filehandle.readlines()
                    for line in content:
                        current = line
                        hostout.append(current)

                if tempout.__len__()==0:
                    print('[!]Log for  {temp}  is empty!'.format(temp = temp))
                    comp_out.append('[!]Log for  {temp}  is empty!'.format(temp = temp))
                elif hostout.__len__()==0:
                    print('[!]Log for  {host}  is empty!'.format(host = host))
                    comp_out.append('[!]Log for  {host}  is empty!'.format(host = host))
                else: len_check = True

                if len_check:
                    temp_size = os.path.getsize(current_path+'\\logs\\temp\\'+temp)
                    host_size = os.path.getsize(current_path+'\\logs\\hosts\\'+host)

                    if temp_size!=host_size:
                        if temp_size>host_size: 
                            for line in tempout:
                                if hostout.count(line)==0: err_list.append('Line {number}:   '.format(number = tempout.index(line)+1)+line.strip())
                        else:
                            for line in hostout:
                                if tempout.count(line)==0: err_list.append('Line {number}:   '.format(number = hostout.index(line)+1)+line.strip())
                    else:
                        if temp_size>host_size: 
                            for line in tempout:
                                if hostout.count(line)==0: err_list.append('Line {number}:   '.format(number = tempout.index(line)+1)+line.strip())
                    
                    if err_list.__len__()==1:
                        print('[#]No differences were found between logs of {temp} !\n'.format(temp = temp))
                        comp_out.append('[#]No differences were found between logs of {temp} !\n'.format(temp = temp))
                    else:
                        print('[*]Comparison of logs: {temp}'.format(temp = temp))
                        comp_out.append('[*]Comparison of logs: {temp}'.format(temp = temp))
                        print('Size of \\Temp\\ log:  {size1} bytes;  Size of \\Hosts\\ log:  {size2} bytes.'.format(size1 = temp_size, size2 = host_size))
                        comp_out.append('Size of \\Temp\\ log:  {size1} bytes;  Size of \\Hosts\\ log:  {size2} bytes.'.format(size1 = temp_size, size2 = host_size))
                        print('Discrepancies found:')
                        comp_out.append('Discrepancies found:')
                        for line in err_list: 
                            print(line)
                            comp_out.append(line)
                        print()
                        comp_out.append('\n')
            err_list.clear()
    else:
        print('[!]Temp-directory is empty')

    return comp_out