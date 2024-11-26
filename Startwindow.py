# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'Startwindow.ui'
#
# Created by: PyQt5 UI code generator 5.6
#
# WARNING! All changes made in this file will be lost!

from PyQt5 import QtCore, QtGui, QtWidgets
from funcs import *
from scapy import all as cap
import gui


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        self.my_window = MainWindow
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(613, 473)  # 613, 473
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.gridLayout = QtWidgets.QGridLayout(self.centralwidget)
        self.gridLayout.setObjectName("gridLayout")

        # 创建一个 QListWidget 对象，用于显示网络接口列表
        self.net_interfece = QtWidgets.QListWidget(self.centralwidget)
        self.net_interfece.setObjectName("net_interfece")

        # 将 QListWidget 添加到网格布局中，并
        # 创建一个 QToolButton 对象，用于开始捕获数据包
        self.gridLayout.addWidget(self.net_interfece, 0, 0, 1, 1)
        self.Start_capture = QtWidgets.QToolButton(self.centralwidget)
        self.Start_capture.setObjectName("Start_capture")
        self.gridLayout.addWidget(self.Start_capture, 1, 0, 1, 1)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 613, 21))
        self.menubar.setObjectName("menubar")
        self.menuFile = QtWidgets.QMenu(self.menubar)
        self.menuFile.setObjectName("menuFile")
        MainWindow.setMenuBar(self.menubar)

        # 创建状态栏, 并将状态栏设置到主窗口
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        # 创建打开动作，并连接到 load_c 方法
        self.actionOpen = QtWidgets.QAction(MainWindow)
        self.actionOpen.setObjectName("actionOpen")
        self.actionOpen.triggered.connect(self.load_c)

        # 创建开始动作
        self.actionStart = QtWidgets.QAction(MainWindow)
        self.actionStart.setObjectName("actionStart")
        # 创建停止动作
        self.actionStopr = QtWidgets.QAction(MainWindow)
        self.actionStopr.setObjectName("actionStopr")
        # 创建重启动作
        self.actionRestart = QtWidgets.QAction(MainWindow)
        self.actionRestart.setObjectName("actionRestart")
        self.menuFile.addAction(self.actionOpen)

        self.menubar.addAction(self.menuFile.menuAction())

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        # add event handlers heres
        self.Start_capture.clicked.connect(self.start_capture_btn_clicked)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "IP流量分析程序"))
        __sortingEnabled = self.net_interfece.isSortingEnabled()
        self.net_interfece.setSortingEnabled(False)

        #################################################################
        # self.network_interfaces, self.mac_addresses = get_all_interfaces()
        # for ni in self.network_interfaces:
        #     item = QtWidgets.QListWidgetItem()
        #     self.net_interfece.addItem(item)
        #     item.setText(_translate("MainWindow", ni))
            
        for face in cap.get_working_ifaces():
            item = QtWidgets.QListWidgetItem(face.name)
            self.net_interfece.addItem(item)
            item.setText(_translate("MainWindow", face.name))
        #################################################################

        self.net_interfece.setSortingEnabled(__sortingEnabled)
        self.Start_capture.setText(_translate(
            "MainWindow", "Select Network Interface"))
        self.menuFile.setTitle(_translate("MainWindow", "File"))

        self.actionOpen.setText(_translate("MainWindow", "Open"))

        self.actionStart.setText(_translate("MainWindow", "Start"))
        self.actionStopr.setText(_translate("MainWindow", "Stop"))
        self.actionRestart.setText(_translate("MainWindow", "Restart"))

    def start_capture_btn_clicked(self):
        # selected_index = self.net_interfece.currentRow()
        # self.chosen_mac = self.mac_addresses[selected_index]

        self.selected = self.net_interfece.currentItem().text()
        # print(self.chosen_mac)
        #########
        print("selected", self.selected)
        self.newWindow = QtWidgets.QMainWindow()
        self.new_ui = gui.Ui_capturing_window(self.selected, self.my_window)
        self.new_ui.setupUi(self.newWindow)
        self.newWindow.show()
        self.my_window.hide()

    def load_c(self):
        # print("load_c 1")
        self.newWindow = QtWidgets.QMainWindow()
        # print("aaaaaaaaa")
        self.new_ui = gui.Ui_capturing_window(None, self.my_window)
        # print("bbbbbbbbbbbbbbb")
        self.new_ui.setupUi(self.newWindow)
        # print("ccccccccccccccc")
        self.newWindow.show()
        # print("ddddddd")
        self.new_ui.load_c()
        # print("eeeeeee")
        self.my_window.hide()

    def load_err_msg(self):
        msg = QtWidgets.QMessageBox()
        msg.setIcon(QtWidgets.QMessageBox.Critical)
        msg.setWindowTitle("Error Message")
        msg.setText("File not found!")
        msg.exec_()


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
