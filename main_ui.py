from  PySide2 import QtCore
from  PySide2 import QtGui
from PySide2 import QtWidgets

from urllib.request import urlopen
from queue import Queue, Empty
import netifaces
import threading
import select
import socket
import re

import os
import sys
import shutil

from argparse import ArgumentParser
from subprocess import Popen, PIPE
from bs4 import BeautifulSoup as bs
from time import time
import requests


class Ui_MainWindow(object):

        # Setting up all components!!!!!!!!!!!!
        def setupUi(self, MainWindow):
                if not MainWindow.objectName():
                        MainWindow.setObjectName(u"MainWindow")
            
                MainWindow.resize(542, 593)
                sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Fixed, QtWidgets.QSizePolicy.Fixed)
                sizePolicy.setHorizontalStretch(0)
                sizePolicy.setVerticalStretch(0)
                sizePolicy.setHeightForWidth(MainWindow.sizePolicy().hasHeightForWidth())
                MainWindow.setSizePolicy(sizePolicy)
                icon = QtGui.QIcon()
                icon.addFile(u"net.png", QtCore.QSize(), QtGui.QIcon.Normal, QtGui.QIcon.Off)
                MainWindow.setWindowIcon(icon)
                MainWindow.setAutoFillBackground(False)
                MainWindow.setStyleSheet(u"background-color: #262626; \n"
                                "border:1px solid red;\n"
                                "outline-style:dotted;\n"
                                "outline-color:#ffffff;")
                MainWindow.setIconSize(QtCore.QSize(30, 30))
                MainWindow.setTabShape(QtWidgets.QTabWidget.Rounded)
                MainWindow.setDockNestingEnabled(False)

                self.actionClear_Logs = QtWidgets.QAction(MainWindow)
                self.actionClear_Logs.setObjectName(u"actionClear_Logs")

                self.actionHelp = QtWidgets.QAction(MainWindow)
                self.actionHelp.setObjectName(u"actionHelp")

                self.actionAbout = QtWidgets.QAction(MainWindow)
                self.actionAbout.setObjectName(u"actionAbout")

                self.actionExit = QtWidgets.QAction(MainWindow)
                self.actionExit.setObjectName(u"actionExit")

                self.centralwidget = QtWidgets.QWidget(MainWindow)
                self.centralwidget.setObjectName(u"centralwidget")

                self.IP_input = QtWidgets.QLineEdit(self.centralwidget)
                self.IP_input.setObjectName(u"IP_input")
                self.IP_input.setGeometry(QtCore.QRect(60, 10, 211, 31))

                font = QtGui.QFont()
                font.setFamily(u"Bookman Old Style")
                font.setPointSize(10)
                font_mini = QtGui.QFont()
                font_mini.setFamily(u"Bookman Old Style")
                font_mini.setPointSize(9)

                self.IP_input.setFont(font)
                self.IP_input.setLayoutDirection(QtGui.Qt.LeftToRight)
                self.IP_input.setStyleSheet(u"background-color: #f2f2f2;")
                self.IP_input.setEchoMode(QtWidgets.QLineEdit.Normal)
                self.IP_input.setAlignment(QtGui.Qt.AlignCenter)
                self.IP_input.setClearButtonEnabled(False)

                self.Scan_Start = QtWidgets.QPushButton(self.centralwidget)
                self.Scan_Start.setObjectName(u"Scan_Start")
                self.Scan_Start.setGeometry(QtCore.QRect(110, 50, 111, 31))

                font1 = QtGui.QFont()
                font1.setFamily(u"Bookman Old Style")
                font1.setPointSize(10)
                font1.setBold(False)
                font1.setWeight(50)

                self.Scan_Start.setFont(font1)
                self.Scan_Start.setCursor(QtGui.QCursor(QtGui.Qt.PointingHandCursor))
                self.Scan_Start.setStyleSheet(u"QPushButton {\n"
                                        "background-color: #ff9100;\n"
                                        "outline-style: dotted;\n"
                                        "}\n"
                                        "QPushButton:hover {\n"
                                        "background-color: #ff9969;\n"
                                        "}\n"
                                        "QPushButton:pressed {\n"
                                        "background-color: #ff9969;\n"
                                        "color: #ffffff\n"
                                        "}")

                self.Update_DB = QtWidgets.QPushButton(self.centralwidget)
                self.Update_DB.setObjectName(u"Update_DB")
                self.Update_DB.setGeometry(QtCore.QRect(110, 520, 111, 41))
                self.Update_DB.setFont(font1)
                self.Update_DB.setCursor(QtGui.QCursor(QtGui.Qt.PointingHandCursor))
                self.Update_DB.setStyleSheet(u"QPushButton {\n"
                                        "background-color: #ff9100;\n"
                                        "outline-style: dotted;\n"
                                        "}\n"
                                        "QPushButton:hover {\n"
                                        "background-color: #ff9969;\n"
                                        "}\n"
                                        "QPushButton:pressed {\n"
                                        "background-color: #ff9969;\n"
                                        "color: #ffffff\n"
                                        "}")

                self.Compare_Logs = QtWidgets.QPushButton(self.centralwidget)
                self.Compare_Logs.setObjectName(u"Compare_Logs")
                self.Compare_Logs.setGeometry(QtCore.QRect(324, 520, 111, 41))
                self.Compare_Logs.setFont(font)
                self.Compare_Logs.setCursor(QtGui.QCursor(QtGui.Qt.PointingHandCursor))
                self.Compare_Logs.setStyleSheet(u"QPushButton {\n"
                                        "background-color: #ff9100;\n"
                                        "outline-style: dotted;\n"
                                        "}\n"
                                        "QPushButton:hover {\n"
                                        "background-color: #ff9969;\n"
                                        "}\n"
                                        "QPushButton:pressed {\n"
                                        "background-color: #ff9969;\n"
                                        "color: #ffffff\n"
                                        "}")

                self.Main_Out = QtWidgets.QTextEdit(self.centralwidget)
                self.Main_Out.setObjectName(u"Main_Out")
                self.Main_Out.setGeometry(QtCore.QRect(30, 90, 481, 421))

                font2 = QtGui.QFont()
                font2.setFamily(u"Bookman Old Style")#Bahnschrift Light
                font2.setPointSize(9)

                self.Main_Out.setFont(font2)
                self.Main_Out.setStyleSheet(u"background-color: #f2f2f2;")
                self.Main_Out.setVerticalScrollBarPolicy(QtGui.Qt.ScrollBarAsNeeded)
                self.Main_Out.setReadOnly(True)

                self.Info = QtWidgets.QTextEdit(self.centralwidget)
                self.Info.setObjectName(u"Info")
                self.Info.setGeometry(QtCore.QRect(290, 10, 191, 71))
                self.Info.setFont(font_mini)
                self.Info.setStyleSheet(u"QTextEdit {\n"
                                        "background-color: #f2f2f2;\n"
                                        "text-align: center;\n"
                                        "}")
                self.Info.setVerticalScrollBarPolicy(QtGui.Qt.ScrollBarAsNeeded)
                self.Info.setReadOnly(True)

                MainWindow.setCentralWidget(self.centralwidget)

                self.menubar = QtWidgets.QMenuBar(MainWindow)
                self.menubar.setObjectName(u"menubar")
                self.menubar.setGeometry(QtCore.QRect(0, 0, 542, 23))
                self.menubar.setStyleSheet(u"QMenuBar {\n"
                                        "background-color: #ff9100;\n"
                                        "}")

                self.menuFile = QtWidgets.QMenu(self.menubar)
                self.menuFile.setObjectName(u"menuFile")
                self.menuFile.setCursor(QtGui.QCursor(QtGui.Qt.ArrowCursor))
                self.menuFile.setStyleSheet(u"QMenu {\n"
                                        "background-color: #ff9100;\n"
                                        "}\n"
                                        "QMenu:hover {\n"
                                        "background-color: #ff9969;\n"
                                        "}")

                self.menuSupport = QtWidgets.QMenu(self.menubar)
                self.menuSupport.setObjectName(u"menuSupport")
                self.menuSupport.setStyleSheet(u"QMenu {\n"
                                        "background-color: #ff9100;\n"
                                        "}\n"
                                        "QMenu:hover {\n"
                                        "background-color: #ff9969;\n"
                                        "}")

                MainWindow.setMenuBar(self.menubar)

                self.menubar.addAction(self.menuFile.menuAction())
                self.menubar.addAction(self.menuSupport.menuAction())
                self.menuFile.addAction(self.actionClear_Logs)
                self.menuFile.addAction(self.actionExit)
                self.menuSupport.addAction(self.actionHelp)
                self.menuSupport.addAction(self.actionAbout)

                self.get_ips_final()
                txt1 = '\t     Welcome to NetScan application, {user}.\n'.format(user = str(os.getlogin()))
                self.Main_Out.setText(txt1)

                self.retranslateUi(MainWindow)
                QtCore.QMetaObject.connectSlotsByName(MainWindow)

                # #Connecting signals for actions (def-s actually)
                # self.Scan_Start.clicked.connect(TestApp.Scan_click)
    
        # Translation !!!!!!!
        def retranslateUi(self, MainWindow):
                MainWindow.setWindowTitle(QtCore.QCoreApplication.translate("MainWindow", u"NetScan", None))

                self.actionClear_Logs.setText(QtCore.QCoreApplication.translate("MainWindow", u"Clear Logs", None))
                self.actionHelp.setText(QtCore.QCoreApplication.translate("MainWindow", u"Help", None))
                self.actionAbout.setText(QtCore.QCoreApplication.translate("MainWindow", u"About", None))
                self.actionExit.setText(QtCore.QCoreApplication.translate("MainWindow", u"Exit", None))

                self.IP_input.setPlaceholderText(QtCore.QCoreApplication.translate("MainWindow", u"Type IP-address here", None))
                self.Scan_Start.setText(QtCore.QCoreApplication.translate("MainWindow", u"Scan", None))
                self.Update_DB.setText(QtCore.QCoreApplication.translate("MainWindow", u"Update DB", None))
                self.Compare_Logs.setText(QtCore.QCoreApplication.translate("MainWindow", u"Compare Logs", None))
                self.Main_Out.setPlaceholderText("")
                self.Info.setPlaceholderText("")

                self.menuFile.setTitle(QtCore.QCoreApplication.translate("MainWindow", u"File", None))
                self.menuSupport.setTitle(QtCore.QCoreApplication.translate("MainWindow", u"Support", None))

        def TextEdit_text(self):
                line = QtCore.QString
                line = self.IP_input.toPlainText()
                lineList=line.split('\n')
                return lineList
        
        ########################################## IP ##########################################
        def getPublicIp(self):
                try:
                        data = str(urlopen('http://checkip.dyndns.com/').read())
                        garbage, dirty_ip = data.split('Current IP Check</title></head><body>')
                        dirty_ip = dirty_ip.replace('Current IP Address: ','')
                        clear_ip, garbage = dirty_ip.split('</body>')
                        out = 'Public IP:  ' +clear_ip.strip() +'\n'
                        return out
                except Exception:
                        return 'Unable to detect public ip-address\n'

        def get_all_ips(self):
                try:
                        alladdresseslist = []
                        addressstr = ''
                        for ifaceName in netifaces.interfaces():
                                addresses = [i['addr'] for i in netifaces.ifaddresses(ifaceName).setdefault(netifaces.AF_INET, [{'addr':'No IP addr'}] )]
                                if addresses != ['No IP addr'] and addresses != ['127.0.0.1']:
                                         alladdresseslist.append(str(addresses))
                        for address in alladdresseslist: 
                                delta = str(address)
                                delta.replace('[\'','')
                                delta.replace('\']','')
                                addressstr +=delta+'; '

                        # addressstr.replace('[\'','')
                        # addressstr.replace('\']','')
                        addressstr+=' '
                        addressstr.replace(';  ','')

                        out = 'Local IP:   '+addressstr
                        return out
                except Exception:
                        return 'Unable to detect local ip-address'

        def get_ips_final(self):
                Info_text = self.Info.toPlainText()
                Info_text = self.getPublicIp()
                Info_text += self.get_all_ips()
                self.Info.setText(Info_text)
        ########################################## End of IP ##########################################
    
        


class Subaev_NetScan(QtWidgets.QMainWindow, Ui_MainWindow):

        def __init__(self):
                super().__init__()

                self.setupUi(self)
                self.IP_input.deselect()
                self.Scan_Start.clicked.connect(self.Scan_click)
                self.Compare_Logs.clicked.connect(self.Compare_Logs_click)
                self.Update_DB.clicked.connect(self.Update_DB_click)

                self.IP_input.returnPressed.connect(self.Scan_click)

                self.actionExit.triggered.connect(self.close) 
                self.actionAbout.triggered.connect(self.About_click) 
                self.actionHelp.triggered.connect(self.Help_click) 
                self.actionClear_Logs.triggered.connect(self.Clear_Logs_click) 



        ########################### Actions per Signals comming !!!!!! ############################
        def closeApp(self):
                self.close()

        def Help_click(self):
                hlp_msg = QtWidgets.QMessageBox()
                hlp_msg.setIcon(QtWidgets.QMessageBox.Information)

                hlp_msg.setWindowTitle("[*] HELP")
                hlp_msg.setText("\t                    There are some helpful tips here.\n\nIn the upper right corner you can find information about current hosts' ip-addresses: public and local.\n"+
                'In the upper left corner there is a text input field and a button to start scanning. Before pressing the button you have to text ipv4 of network (x.x.x.x/24) or'+
                'of net host. After all this, the scan will start, which may take some time.\n\n[!] The program may be displayed as unavailable during scanning.'+
                ' This is normal as long as the network part of the scan is running.\nAfter the analysis is complete, all the information will be displayed in the main window,'+
                ' located in the center.\n\nThere are also an Update DB and a Compare Logs buttons. The first one overwrites data from a temporary directory to a permanent one.\n'+
                'The second one is responsible for comparing output data that is written to a temporary directory with data from a permanent folder. This is necessary so that you'+
                ' can immediately compare the configuration of the scanned node with its configuration (if there is one) in the permanent directory after scanning.\n\n'+
                'You can also clear the temporary directory or exit the program in the "File" menu.\nAnd in the "Help" menu, you can get reference information '+
                '(which you are currently reading :)) or see a summary of the application.\n\nAll Folders are located in <path_to_programm>\\logs and inside that there are two more:\n'+
                '\\temp and \\hosts, where temp- temporery files folder and hosts- permanent ones. Do not move or delete any files other than those located in these two directories!')
                hlp_msg.setInformativeText("\t              Designed and implemented by Subaev RN.")
                hlp_msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                hlp_msg.exec()

        def About_click(self):
                about_msg = QtWidgets.QMessageBox()
                about_msg.setIcon(QtWidgets.QMessageBox.Information)

                about_msg.setWindowTitle("[*] ABOUT")
                about_msg.setText("\tThis program is designed for network analysis.\n\nYou can always check the outputs and any logs in "+
                "\\logs & \\logs\\Temp & \n\\logs\\Hosts directories. For start type ipv4-address and click on \"Scan\".")
                about_msg.setInformativeText("\t   Designed and implemented by Subaev RN.")
                about_msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                about_msg.exec() 

        def Clear_Logs_click(self):
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
                
                def dir(extrapath):
                        selfpath = str(os.getcwd()).replace('main_ui.py','')
                        selfpath+=extrapath
                        # print(sys.modules[__name__])
                        dirpath = list(os.listdir(path=selfpath))

                        return dirpath
                
                tempdir = dir('\\logs\\temp')
                selfpath = str(os.getcwd()).replace('main_ui.py','')

                if tempdir.__len__()==0:
                        empty_msg = QtWidgets.QMessageBox()
                        empty_msg.setIcon(QtWidgets.QMessageBox.Warning)

                        empty_msg.setWindowTitle("[!] EMPTY DIR")
                        empty_msg.setText("The directory {cur}\\logs\\temp\\ is empty.\n\nSo, you can scan any hosts previously.\n".format(cur = selfpath))
                        empty_msg.setInformativeText("Nothing was cleared.")
                        empty_msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                        empty_msg.exec()
                else:
                        for every in tempdir:
                                del_path = selfpath+'\\logs\\temp\\'+every
                                del_file(del_path)

                        done_msg = QtWidgets.QMessageBox()
                        done_msg.setIcon(QtWidgets.QMessageBox.Information)

                        done_msg.setWindowTitle("[*] Done")
                        done_msg.setText("The directory {cur}\\logs\\temp\\ cleanup was successful!\n".format(cur = selfpath))
                        done_msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                        done_msg.exec()

        def Compare_Logs_click(self):
                def dir(extrapath):
                        selfpath = str(os.getcwd()).replace('main_ui.py','')
                        selfpath+=extrapath
                        # print(sys.modules[__name__])
                        dirpath = list(os.listdir(path=selfpath))

                        return dirpath

                def compare_res():
                        comp_out = []
                        err_list = []
                        len_check = False
                        tempdir = dir('\\logs\\temp')
                        hostsdir = dir('\\logs\\hosts')
                        current_path = str(os.getcwd()).replace('main_ui.py','')

                        if tempdir.__len__()>0:
                            comp_out.append('Comparing data from \\Temp\\ dir to \\Hosts\\ dir.\n')
                            for temp in tempdir:
                                err_list.append('The line numbering is based on a largest log.\n')

                                if hostsdir.count(temp)==0:
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
                                        comp_out.append('[!]Log for  {temp}  is empty!'.format(temp = temp))
                                    elif hostout.__len__()==0:
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
                                            comp_out.append('[#]No differences were found between logs of {temp} !\n'.format(temp = temp))
                                        else:
                                            comp_out.append('[*]Comparison of logs: {temp}'.format(temp = temp))
                                            comp_out.append('Size of \\Temp\\ log:  {size1} bytes;  Size of \\Hosts\\ log:  {size2} bytes.'.format(size1 = temp_size, size2 = host_size))
                                            comp_out.append('Discrepancies found:')
                                            for line in err_list: 
                                                comp_out.append(line)
                                            comp_out.append('\n')
                                err_list.clear()

                        return comp_out
                
                final_out = compare_res()
                current_path = str(os.getcwd()).replace('main_ui.py','')
                if final_out.__len__()<2:
                        err = QtWidgets.QMessageBox()
                        err.setIcon(QtWidgets.QMessageBox.Warning)

                        err.setWindowTitle("[!] Empty")
                        err.setText("The directory {cur}\\logs\\temp\\ is empty.\n\nSo, you can scan any hosts previously.\n".format(cur = current_path))
                        err.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                        compare_wr = open('{cur}//logs//temp//compare_results.txt'.format(cur = current_path), 'w')

                        err.exec()
                else:
                        done = QtWidgets.QMessageBox()
                        # done.setMinimumWidth(200)
                        done.setIcon(QtWidgets.QMessageBox.Information)

                        done.setWindowTitle("[*] Comparison completed")
                        done.setText('\tThe comparison was completed successfully.'+
                        '                                                           '+
                        '\t  Click on detailed-definition for more info.'+
                        '                                               '+
                        '\t                          Outputs saved at \\logs\\ as\n\t                 compare_results.txt')
                        final_str = ''
                        for every in final_out:
                                final_str+=every+'\n'
                        done.setDetailedText(final_str)
                        done.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                        compare_wr = open('{cur}//logs//compare_results.txt'.format(cur = current_path), 'w')
                        compare_wr.write(final_str)
                        # for lines in out443:
                        #         compare_wr.write(lines+'\n')
                        compare_wr.close()

                        done.exec()

        def Update_DB_click(self):
                current_path = str(os.getcwd()).replace('main_ui.py','')

                def dir(extrapath):
                    path=''
                    path+=current_path+extrapath
                    # print(sys.modules[__name__])
                    dirpath = list(os.listdir(path=path))

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
                    shutil.copy("{cur}\\logs\\temp\\{p}".format(cur = current_path, p = filename), "{cur}\\logs\\hosts".format(cur = current_path))

                def update():
                        tempdir = dir('\\logs\\temp')
                        hostsdir = dir('\\logs\\hosts')

                        if tempdir.__len__()>0:
                            for every in tempdir:
                                if hostsdir.count(every)==0:
                                    outtemp1 = []

                                    with open('{cur}\\logs\\temp\\{ev}'.format(cur = current_path, ev = every), 'r') as filehandle:  
                                        content = filehandle.readlines()
                                        for line in content:
                                            current = line[:-1]
                                            outtemp1.append(current)

                                    if outtemp1.__len__()>0: copy_file(every)
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
                                            del_file(delpath)
                                            copy_file(every)
                                        else:
                                            delpath = current_path+'\\logs\\hosts\\'+str(every)
                                            del_file(delpath)
                                            copy_file(every)
                            
                            done = QtWidgets.QMessageBox()
                            done.setIcon(QtWidgets.QMessageBox.Information)

                            done.setWindowTitle("[*] Successfully updated")
                            done.setText("The main-log files from {cur}\\logs\\hosts were successfully updated!\n".format(cur = current_path))
                            done.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                            done.exec()
                        else:
                            er = QtWidgets.QMessageBox()
                            er.setIcon(QtWidgets.QMessageBox.Warning)

                            er.setWindowTitle("[!] Temp-directory is empty")
                            er.setText("Temp-directory {cur}\\logs\\temp is empty!\n".format(cur = current_path))
                            er.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                            er.exec()
                update()

        ############################################################ SCAN_BUT_Clicked ############################################################
        # def Scan_click(self):
        #         ip_in = str(self.IP_input.text())

        #         msg = QtWidgets.QMessageBox()
        #         msg.setIcon(QtWidgets.QMessageBox.Warning)

        #         msg.setWindowTitle("[!]ERROR")
        #         msg.setText("[!] An error occured...\nCheck the input please and try again.")
        #         msg.setDetailedText("You should to correctly input the ipv4 address of host or network for start scan.\n\nYou also can read the Help content.")
        #         msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

        #         if ip_in.__len__()!=0 and ip_in!='Type IP-address here': 
        def Osnova(self):
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
                                        nettemp2 = open('logs//temp//host_scan_temp.txt', 'a')
                                        nettemp2.write("\nfound-title:           {title}".format(title=title_str))
                                        nettemp2.close()

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
                                finish = 1

                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                nettemp.write("\n[!]Can't establish the connection to {port} port!".format(port=errport))
                                nettemp.close()

                                return finish
                            except:
                                finish = 1

                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                nettemp.write('\n[!]An Error occurance in web-scan {port} port! (probably cause sites\' security)'.format(port=errport))
                                nettemp.close()

                                return finish

                        def run_nmap_scan_list(self,ip_address):
                            nettemp = open('logs//temp//net_scan_temp.txt', 'a')

                            txt = self.Main_Out.toPlainText()
                            txt += '\n[*] Scan process for network {ip_address} started...\n'.format(ip_address=ip_address)
                            self.Main_Out.setText(txt)
                            nettemp.write('[*] Scan process for network {ip_address} started...\n\n'.format(ip_address=ip_address))

                            nmap_process = Popen(['nmap.exe','-sn','-v','-oN','logs/netscan-nmap-out-net.txt',ip_address], stdout=PIPE, stderr=PIPE)
                            start_time  = time()

                            while True:
                                output_line = nmap_process.stdout.readline()
                                if output_line:
                                    output_line = output_line.decode()
                                    f_out = str(output_line).lower()
                                    if f_out.find('host down')==-1:
                                        if f_out.find('nmap scan report for ')!=-1: nettemp.write('\n'+f_out.strip()+'\n')
                                        else: nettemp.write(f_out.strip()+'\n')
                                else:
                                    break
                            
                            stop_time = time() - start_time
                            sec, milsec = str(stop_time).split('.')
                            sec+='.'+milsec[0]+milsec[1]+milsec[2]

                            nettemp.write('\n[*] Process for {ip_address} done! Elapsed time: {elapsed_time}\n\n'.format(ip_address=ip_address, elapsed_time=sec))
                            nettemp.close()

                            wri = '\t     Welcome to NetScan application, {user}.\n\n'.format(user = str(os.getlogin()))
                            txt = open('logs//temp//net_scan_temp.txt', 'r')
                            for line in txt: wri +=line
                            self.Main_Out.setText(wri)


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
                                        nettemp.write('\n\tDiscovered MAC address')

                                        regex_mac_address = re.search('([0-9A-F]{2}[:-]){5}([0-9A-F]{2})', output_line, re.I) #out --> Match
                                        if regex_mac_address:
                                            mac_address = regex_mac_address.group()
                                            host_info['mac-address'] = mac_address

                                    elif re.match(pattern_os, output_line):
                                        nettemp.write('\n\tDiscovered the most probable OS')

                                        os = re.split(':', output_line)[1]
                                        if os:
                                            os = os.strip()
                                            host_info['operating-system'] = os

                                    elif re.match(pattern_os_CPE, output_line):
                                        nettemp.write('\n\tDiscovered OS-CPE')

                                        os_cpe = re.split('CPE:', output_line)[1]
                                        if os_cpe:
                                            os_cpe = os_cpe.strip()
                                            host_info['os-cpe'] = os_cpe

                                    elif re.match(pattern_device_type, output_line):
                                        nettemp.write('\n\tDiscovered the most probable device type')

                                        device_type = re.split(':', output_line)[1]
                                        if device_type:
                                            device_type = device_type.strip()
                                            host_info['device-type'] = device_type

                                    elif re.match(pattern_uptime, output_line):
                                        nettemp.write('\n\tDiscovered the uptime')

                                        uptime = re.split('guess: ', output_line)[1]
                                        if uptime:
                                            uptime = uptime.strip()
                                            host_info['uptime'] = uptime

                                    elif re.match(pattern_open_port, output_line):
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

                            nettemp.write('\n[***] NMAP process for {ip_address} done! Elapsed time: {elapsed_time}'.format(ip_address=ip_address, elapsed_time=sec))
                            nettemp.close()
                            
                            return host_info

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

                            # out_80_txt = ''
                            if len(port80_out)!=0:
                                data = []
                                with open('logs/port_80_out.txt', 'r') as fil:
                                    for line in fil:
                                        line.strip().replace('\n','')
                                        data.append([float(x) for x in line.split()])

                                f = open('logs/port_80_out.txt', 'w')
                                for index in data:
                                    f.write(index)
                                f.close()
                            
                            out_443_txt = ''
                            if len(port443_out)!=0:
                                f = open('logs/port_80_out.txt', 'r')
                                i=0
                                for index in out_443_txt:
                                    if i==0: out_443_txt+=index
                                    elif i!=0 and index.strip()!='\n':
                                        out_443_txt+=index
                                    else: i+=1
                                f.close()

                                f = open('logs/port_80_out.txt', 'w')
                                for index in out_443_txt:
                                    f.write(index)
                                f.close()

                        def DevT_http_https():
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
                                    pc_perc = 65
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
                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                com_f = '\n'+com+'\n'
                                nettemp.write(com_f)
                                nettemp.close()
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
                                    elif port == 23: connect.append(str(port)+'- telnet')
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
                                nettemp.write('\nsignature ports:     {l}'.format(l=signatures))
                            if len(connect)!=0: 
                                nettemp.write('\nconnect&fs ports:    {l}'.format(l=connect))
                            if len(web)!=0: 
                                nettemp.write('\nweb ports:           {l}'.format(l=web))
                            if len(private)!=0: 
                                nettemp.write('\nprivate-using ports: {l}'.format(l=private))
                            if len(others)!=0: 
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
                            elif mac_address.find('00:12:16')!=-1 or mac_address.find('00.12.16')!=-1 or mac_address.find('00-12-16')!=-1:
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
                            nettemp = open('logs//temp//host_scan_temp.txt', 'a')

                            for key, value in detail_out.items():
                                nettemp.write('\n')
                                nettemp.write('{key}:   {value}'.format(key=key, value=value))

                            if model != '':
                                nettemp.write('\nFinal model:         {model}'.format(model=model))
                            else:
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

                        ############ IP IP IP ############
                        def getPublicIp(Net,Print):
                            try:
                                data = str(urlopen('http://checkip.dyndns.com/').read())
                                # data = '<html><head><title>Current IP Check</title></head><body>Current IP Address: 65.96.168.198</body></html>\r\n'
                                if Net:
                                    nettemp = open('logs//temp//net_scan_temp.txt', 'a')
                                    nettemp.write('\tYour public ip:  '+re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1))
                                    nettemp.close()
                                else:
                                    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                    nettemp.write('\tYour public ip:  '+re.compile(r'Address: (\d+\.\d+\.\d+\.\d+)').search(data).group(1))
                                    nettemp.close()
                            except Exception:
                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                nettemp.write('\n\ttUnable to detect your public ip.\n')
                                nettemp.close()

                        def get_all_ips(Net,Print):
                            try:
                                alladdresseslist = []
                                for ifaceName in netifaces.interfaces():
                                    addresses = [i['addr'] for i in netifaces.ifaddresses(ifaceName).setdefault(netifaces.AF_INET, [{'addr':'No IP addr'}] )]
                                    if addresses != ['No IP addr']:
                                        alladdresseslist.append(addresses)
                                if Net:
                                    nettemp = open('logs//temp//net_scan_temp.txt', 'a')
                                    nettemp.write('\n\tYour local ip:   '+str(alladdresseslist))
                                    nettemp.close()
                                else:
                                    nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                    nettemp.write('\n\tYour local ip:   '+str(alladdresseslist))
                                    nettemp.close()
                            except Exception:
                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                nettemp.write('\n\tUnable to detect your local ip.\n')
                                nettemp.close()

                        def get_ips_final(Net,Print):
                            getPublicIp(Net,Print)
                            get_all_ips(Net,Print)   
                        ############  END OF IP IP IP ############

                        ############ OS OS OS ############
                        def dir_loc(extrapath):
                            current_path = str(os.getcwd()).replace('main_ui.py','')
                            current_path+=extrapath
                            dirpath = list(os.listdir(path=current_path))

                            return dirpath
                        def del_file_loc(path):
                                try:
                                    if os.path.isfile(path):
                                        os.remove(path)
                                    else:
                                        # print("Error: %s file not found" % path)
                                        pass
                                except OSError as e:
                                    # print ("Error: %s - %s." % (e.filename, e.strerror))
                                    pass
                        def rename_static(Net,ip):   
                                try: 
                                    current_path = str(os.getcwd()).replace('main_ui.py','')
                                    if Net:
                                        del_file_loc('{cur}\\logs\\temp\\net_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
                                        os.rename("{cur}\\logs\\temp\\net_scan_temp.txt".format(cur = current_path),'{cur}\\logs\\temp\\net_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
                                    else:   
                                        f_list = dir_loc('\\logs\\temp')
                                        f_txt = False
                                        for one in f_list:
                                            if one=='host_scan_temp.txt':f_txt=True
                                        
                                        if f_txt:
                                            del_file_loc('{cur}\\logs\\temp\\host_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
                                            os.rename('{cur}\\logs\\temp\\host_scan_temp.txt'.format(cur = current_path),'{cur}\\logs\\temp\\host_{ipaddr}_out.txt'.format(cur = current_path, ipaddr = ip))
                                except Exception as e:
                                    print(e)
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
                        ############ END OF OS OS OS ############



                        try:
                            ############# STARTING #############
                            clean_up_logs()

                            global ip, key
                            key = 0

                            txt1 = self.Main_Out.toPlainText()
                            txt1 = '\t     Welcome to NetScan application, {user}.\n'.format(user = str(os.getlogin()))
                            self.Main_Out.setText(txt1)

                            ip = self.IP_input.text()

                            if ip.__len__()>18 or ip.__len__()<7 or ip.count('.')!=3:
                                err = QtWidgets.QMessageBox()
                                err.setIcon(QtWidgets.QMessageBox.Warning)

                                err.setWindowTitle("[?] Invalid Input")
                                err.setText("You have to type a correct ipv4-address of host previously!\n")
                                err.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                                err.exec()  

                            ### NETWORK SCANNING LAUNCH ###    
                            if ip and key == 0:
                                if str(ip).find('/24') != -1 or str(ip).find('\\24') != -1:
                                    open('logs//temp//net_scan_temp.txt', 'w').close()
                                    if str(ip).find('\\24') != -1:
                                        ip = str(ip).replace('\\','/')
                                        run_nmap_scan_list(self,ip)

                                    else:
                                        run_nmap_scan_list(self,ip)
                                    get_ips_final(True, True)
                                    validip = str(ip).replace('/','(')
                                    validip = str(validip).replace('\\','(')
                                    validip+=')'
                                    rename_static(True, validip)
                                else: key = 2

                            ### HOST SCANNING LAUNCH ###    
                            if ip and key!=0:
                                open('logs//temp//host_scan_temp.txt', 'w').close()
                                nettemp = open('logs//temp//host_scan_temp.txt', 'a')
                                nettemp.write('\n')
                                if key == 1:
                                    get_ips_final(False, False)
                                    run_nmap_scan(ip)
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
                                        nettemp.write('\n{key}:'.format(key=key))
                                        for v in value:
                                            nettemp.write('\n\t{v}'.format(v=v))
                                    else:
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

                                web_impl()
                                
                                wri_fin = ''
                                timer = 0
                                future_text = open('logs//temp//host_scan_temp.txt', 'r')
                                for line in future_text: 
                                    if timer>=3: wri_fin +=line
                                    timer+=1
                                self.Main_Out.setText(wri_fin)
                                future_text.close()

                                rename_static(False, self.IP_input.text())

                        except Exception:
                            pass

        ############################################################ END OF SCAN_BUT_Clicked ############################################################

        def Scan_click(self):
                ip_in = str(self.IP_input.text())

                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Warning)

                msg.setWindowTitle("[!]ERROR")
                msg.setText("[!] An error occured...\nCheck the input please and try again.")
                msg.setDetailedText("You should to correctly input the ipv4 address of host or network for start scan.\n\nYou also can read the Help content.")
                msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                if ip_in.__len__()!=0 and ip_in!='Type IP-address here': self.Osnova()
                else: msg.exec()
        

                
if __name__ == '__main__':
        import sys

        app = QtWidgets.QApplication(sys.argv)
        WND = Subaev_NetScan()
        WND.show()                   
        sys.exit(app.exec_())