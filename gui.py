# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'gui.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!
import subprocess
import numpy as np
from PyQt5 import QtCore, QtGui, QtWidgets
from funcs import *
from scapy.all import *
from scapy.arch.common import compile_filter
import netifaces as nif
import psutil
from threading import Thread
import time
import datetime
import socket
from input_dialogue import *

class Ui_capturing_window():
    def __init__(self, mac, start_window):
        #print("Ui_capturing_window")
        self.chosen_mac = mac
        #print("constructoooooooooooooooooor")
        #print(self.chosen_mac)
        self.capturing_status = True
        self.isStop = False
        self.ip_protocols = {num:name[8:] for name,num in vars(socket).items() if name.startswith("IPPROTO")}
        self.window_to_reshow = start_window


    def setupUi(self, MainWindow):
        self.my_window = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(1000, 800)  # 676, 545
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName("verticalLayout")
        self.Search = QtWidgets.QLineEdit(self.centralwidget)
        self.Search.setObjectName("Search")
        self.verticalLayout.addWidget(self.Search)
        self.Search.editingFinished.connect(self.check)
        # self.Searchbutton = QtWidgets.QToolButton(self.centralwidget)
        # self.Searchbutton.setObjectName("Searchbutton")
        # self.verticalLayout.addWidget(self.Searchbutton)
        self.Packets_table = QtWidgets.QTableWidget(self.centralwidget)
        self.Packets_table.setObjectName("Packets")
        self.Packets_table.setColumnCount(5)
        self.Packets_table.setRowCount(0)
        self.Packets_table.setColumnWidth(0,200) ###########################
        self.Packets_table.itemSelectionChanged.connect(self.selected_change)

        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(3, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(4, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(5, item)
        item = QtWidgets.QTableWidgetItem()
        self.Packets_table.setHorizontalHeaderItem(6, item)
        self.verticalLayout.addWidget(self.Packets_table)
        self.line_2 = QtWidgets.QFrame(self.centralwidget)
        self.line_2.setFrameShape(QtWidgets.QFrame.HLine)
        self.line_2.setFrameShadow(QtWidgets.QFrame.Sunken)
        self.line_2.setObjectName("line_2")
        self.verticalLayout.addWidget(self.line_2)

        self.pack_details = QtWidgets.QTextBrowser(self.centralwidget)
        self.pack_details.setObjectName("pack_hex")
        self.verticalLayout.addWidget(self.pack_details)

        self.pack_raw = QtWidgets.QTextBrowser(self.centralwidget)
        self.pack_raw.setObjectName("pack_hex")
        self.verticalLayout.addWidget(self.pack_raw)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 676, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        self.menuCapture = QtWidgets.QMenu(self.menubar)
        self.menuCapture.setObjectName("menuCapture")
        self.menuHelp = QtWidgets.QMenu(self.menubar)
        self.menuHelp.setObjectName("menuHelp")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionOpen.triggered.connect(self.load_c)


        self.actionSave = QtWidgets.QAction(MainWindow)
        self.actionSave.setObjectName("actionSave")
        self.actionSave.triggered.connect(self.save_c)

        self.actionBack = QtWidgets.QAction(MainWindow)
        self.actionBack.setObjectName("actionBack")
        self.actionBack.triggered.connect(self.back_c)


        self.actionClear = QtWidgets.QAction(MainWindow)
        self.actionClear.setObjectName("actionClear")
        self.actionClear.triggered.connect(self.clear_c)


        self.actionStart = QtWidgets.QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        self.actionStart.triggered.connect(self.start_c)
        
        self.actionHelp = QtWidgets.QAction(MainWindow)
        self.actionHelp.setObjectName("actionHelp")
        self.actionHelp.triggered.connect(self.help_c)


        self.actionStop = QtWidgets.QAction(MainWindow)
        self.actionStop.setObjectName("actionStop")
        self.actionStop.triggered.connect(self.stop_c)


        self.menuFile.addAction(self.actionOpen)
        self.menuFile.addAction(self.actionSave)
        self.menuFile.addAction(self.actionBack)


        self.menuCapture.addAction(self.actionStart)
        self.menuCapture.addAction(self.actionStop)
        self.menuCapture.addAction(self.actionClear)
        
        self.menuHelp.addAction(self.actionHelp)

        self.menubar.addAction(self.menuFile.menuAction())
        self.menubar.addAction(self.menuCapture.menuAction())
        self.menubar.addAction(self.menuHelp.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # self.Searchbutton.clicked.connect(self.filter_c)

    def check(self):
        f=self.Search.text()
        try:
            compile_filter(f)
            self.Search.setStyleSheet("background-color: green")
        except:
            self.Search.setStyleSheet("background-color: red")

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "capturing window"))
        self.Search.setText(_translate("MainWindow", "ip6"))
        # self.Searchbutton.setText(_translate("MainWindow", "Search"))

        item = self.Packets_table.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Time"))
        item = self.Packets_table.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Source"))
        item = self.Packets_table.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Destination"))
        item = self.Packets_table.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Protocol"))
        item = self.Packets_table.horizontalHeaderItem(4)
        item.setText(_translate("MainWindow", "Length"))
        #item = self.Packets_table.horizontalHeaderItem(5)
        #item.setText(_translate("MainWindow", "Info"))

        self.menuFile.setTitle(_translate("MainWindow", "File"))
        self.menuCapture.setTitle(_translate("MainWindow", "Capture"))
        self.menuHelp.setTitle(_translate("MainWindow", "Help"))
        self.actionOpen.setText(_translate("MainWindow", "Open"))
        self.actionSave.setText(_translate("MainWindow", "Save"))
        self.actionBack.setText(_translate("MainWindow", "Back"))
        self.actionClear.setText(_translate("MainWindow", "Clear"))
        self.actionStart.setText(_translate("MainWindow", "Start"))
        self.actionStop.setText(_translate("MainWindow", "Stop"))
        self.actionHelp.setText(_translate("MainWindow", "Help"))


    def reshow(self):
        self.window_to_reshow.show()


    def back_c(self):
        self.reshow()
        self.my_window.close()

    def filter_c(self):
        f = self.Search.text()
        self.clear_c()

        if f is None:
            for p in self.pckts:
                try:
                    rowPosition = self.Packets_table.rowCount()
                    self.Packets_table.insertRow(rowPosition)
                    self.Packets_table.setItem(rowPosition, 0,
                                               QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
                    self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                    self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                    self.Packets_table.setItem(rowPosition, 3,
                                               QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                    self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(p[IP].len)))
                except:
                    pass
        else:
            for p in self.pckts:
                try:
                    search_here = [p.sport, p.dport, 
                                   str(self.ip_protocols[int(p[IP].proto)]), 
                                   p[IP].src, p[IP].dst]
                    if f in search_here:
                        rowPosition = self.Packets_table.rowCount()
                        self.Packets_table.insertRow(rowPosition)
                        self.Packets_table.setItem(rowPosition, 0,
                                                   QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
                        self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                        self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                        self.Packets_table.setItem(rowPosition, 3,
                                                   QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                        self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(p[IP].len)))

                except:
                    pass

    def start_c(self):
        if self.chosen_mac is None:
            self.back_c()
        print("SnifferStart")
        self.isStop = False
        sniffer = Thread(target=self.threaded_sniff_target)
        sniffer.daemon = True
        sniffer.start()
        # print("sniffer started")


    def stop_c(self):
        print("Sniffer stoped")
        self.isStop = True
        
    def get_packet_layers(self, packet):
        counter = 0
        while True:
            layer = packet.getlayer(counter)
            if layer is None:
                break
            yield layer
            counter += 1

    def sniffed_packet(self, packet: scapy.packet.Packet) -> None:
        # print("sniffed")
        # print(packet.show())
        # if IP in packet:
        print("src", packet.src, mac_for_ip(packet.src))
        print("dst", packet.dst, mac_for_ip(packet.dst))
        
        # get the protocol of the packet
        layer = None
        for var in self.get_packet_layers(packet):
            if not isinstance(var, (Padding, Raw)):
                layer = var
        protocol = layer.name
        
        # length
        length = f"{len(packet)}"
        
        rowPosition = self.Packets_table.rowCount()
        self.Packets_table.insertRow(rowPosition)
        self.Packets_table.setItem(
            rowPosition, 0, QtWidgets.QTableWidgetItem(
                str(datetime.datetime.fromtimestamp(packet.time))))
        self.Packets_table.setItem(
            rowPosition, 1, QtWidgets.QTableWidgetItem(packet.src))
        self.Packets_table.setItem(
            rowPosition, 2, QtWidgets.QTableWidgetItem(packet.dst))
        self.Packets_table.setItem(
            rowPosition, 3, QtWidgets.QTableWidgetItem(protocol))
        self.Packets_table.setItem(
            rowPosition, 4, QtWidgets.QTableWidgetItem(length))

    # def isRequired(self, packet:scapy.packet.Packet)->bool:
    #     if packet.type == 'IPv6':
    #         return True
    #     return False

    def threaded_sniff_target(self):
        # sniff(prn=lambda x: print(str(x)))
        print("threaded_sniff_target")
        f = self.Search.text()  # 'ip6 proto'       
        self.pckts = sniff(prn=self.sniffed_packet, 
                           filter=f,
                           stop_filter=lambda x: self.isStop)


    def selected_change(self):
        index = self.Packets_table.currentRow()
        p = self.pckts[index]
        #print(index)
        #print(str(hexdump(self.pckts[0])))

        #print("hexdump : \n",funcs.hexdump(s))
        #print(s)
        b = p.show
        p.show()
        try:
            #raw_load = self.pckts[index][Raw].load
            #print("raw load:", type(raw_load), raw_load)
            #base64_load = base64.b64encode(raw_load)
            #print("base64 :", type(base64_load), base64_load )
            #hb = base64_load.decode()
            #print("decoded :",type(hb), hb)

            e = str(b).index("<Raw")
            hex_dump = my_hexdump2(p)
            self.pack_raw.setText(hex_dump)
            hexdump(p)
            hd2 = my_hexdump2(p)
            #print("hd2 : \n", hd2)

        except:
            e = -1
            self.pack_raw.setText(" ")

        self.pack_details.setText((("\n" + "-"*150 + "\n").join(str(b)[28: e].split("|"))).replace(" ","\n"))

        #self.pack_details.setText(str(index))
        #print("------------",str(p[self.ip_protocols[int(p[IP].proto)]].payload))


    def save_c(self):
        try:
            dialouge_box = Dialouge()
            self.file_name = dialouge_box. initUI(save=True)
            wrpcap(self.file_name, self.pckts)
        except:
            self.save_err_msg()


    def load_c(self):
        #print("load_c 2")
        try:
            dialouge_box = Dialouge()
            self.file_name = dialouge_box.initUI()

            self.pckts = rdpcap(self.file_name)
            self.clear_c()
            for p in self.pckts:
                rowPosition = self.Packets_table.rowCount()
                self.Packets_table.insertRow(rowPosition)
                self.Packets_table.setItem(rowPosition, 0,
                                           QtWidgets.QTableWidgetItem(str(datetime.datetime.fromtimestamp(p.time))))
                self.Packets_table.setItem(rowPosition, 1, QtWidgets.QTableWidgetItem(p[IP].src))
                self.Packets_table.setItem(rowPosition, 2, QtWidgets.QTableWidgetItem(p[IP].dst))
                self.Packets_table.setItem(rowPosition, 3,
                                           QtWidgets.QTableWidgetItem(self.ip_protocols[int(p[IP].proto)]))
                self.Packets_table.setItem(rowPosition, 4, QtWidgets.QTableWidgetItem(str(p[IP].len)))

        except:
            self.load_err_msg()

    def clear_c(self):
        self.Packets_table.setRowCount(0)
        self.pack_raw.setText("")
        self.pack_details.setText("")


    def save_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("couldn't save file")
        msg.exec_()


    def load_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("select an existing file to be loaded")
        msg.exec_()

    def help_c(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Information)
        msg.setWindowTitle("Help")
        msg.setText("这是一个Packet-Sniffer工具，在开始使用该软件之前，你应该先安装Npcap。开始sniff之前，你需要先设置过滤条件，然后点击Start按钮。下面是一些常用的过滤条件：\n ip6: 只显示ipv6的数据包\n ip6 proto udp: 只显示ipv6协议为udp的数据包\n ip6 proto udp and port 53: 只显示ipv6协议为udp且端口为53的数据包\n ip6 proto udp and port 53 and host www.baidu.com: 只显示ipv6协议为udp且端口为53且host地址为www.baidu.com的数据包\n")
        msg.exec_()




if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_capturing_window("64:5a:04:b4:6a:1c")
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

