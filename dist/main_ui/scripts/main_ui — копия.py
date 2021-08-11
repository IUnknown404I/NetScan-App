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
                font2.setFamily(u"Bahnschrift Light")
                font2.setPointSize(10)

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
                        # print(data)
                        garbage, dirty_ip = data.split('Current IP Check</title></head><body>')
                        dirty_ip = dirty_ip.replace('Current IP Address: ','')
                        clear_ip, garbage = dirty_ip.split('</body>')
                        out = '    Public IP:  ' +clear_ip.strip() +'\n'
                        return out
                except Exception:
                        print('\tUnable to detect public ip-address')
                        return 'Unable to detect public ip-address\n'

        def get_all_ips(self):
                try:
                        alladdresseslist = []
                        addressstr = ''
                        for ifaceName in netifaces.interfaces():
                                addresses = [i['addr'] for i in netifaces.ifaddresses(ifaceName).setdefault(netifaces.AF_INET, [{'addr':'No IP addr'}] )]
                                if addresses != ['No IP addr']:
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
                        print('\tUnable to detect local ip-address')
                        return 'Unable to detect local ip-address'

        def get_ips_final(self):
                Info_text = self.Info.toPlainText()
                Info_text = self.getPublicIp()
                Info_text += self.get_all_ips()
                self.Info.setText(Info_text)
        ########################################## End of IP ##########################################
    
        


class TestApp(QtWidgets.QMainWindow, Ui_MainWindow):
        def __init__(self):
                super().__init__()

                self.setupUi(self)
                self.IP_input.deselect()
                self.Scan_Start.clicked.connect(self.Scan_click)
                self.Compare_Logs.clicked.connect(self.Compare_Logs_click)
                self.Update_DB.clicked.connect(self.Update_DB_click)

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
                hlp_msg.setText("\tThis program is designed for network analysis.\n\nYou can always check the outputs and any logs in "+
                "\\logs & \\logs\\Temp & \\logs\\Hosts directories.")
                hlp_msg.setInformativeText("\t    Designed and implemented by Subaev RN.")
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
                print(tempdir)
                selfpath = str(os.getcwd()).replace('main_ui.py','')
                print(selfpath)

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
                        '\t              Outputs saved at \\logs\\ as compare_results.txt')
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
        def Scan_click(self):
                ip_in = str(self.IP_input.text())
                msg = QtWidgets.QMessageBox()
                msg.setIcon(QtWidgets.QMessageBox.Warning)

                msg.setWindowTitle("[!]ERROR")
                msg.setText("[!] An error occured...\nCheck the input please and try again.")
                msg.setDetailedText("You should to correctly input the ipv4 address of host or network for start scan.\n\nYou also can read the Help content.")
                msg.addButton('OK', QtWidgets.QMessageBox.AcceptRole)

                if ip_in.__len__()!=0 and ip_in!='Type IP-address here': 
                        pass











                
                else:
                        msg.exec()

        ############################################################ END OF SCAN_BUT_Clicked ############################################################
                
if __name__ == '__main__':
        import sys

        app = QtWidgets.QApplication(sys.argv)
        WND = TestApp()
        WND.show()                   
        sys.exit(app.exec_())
