import ast
import csv
from datetime import datetime
import json
import os
import sys
import re
import traceback
import webbrowser
from PyQt5.QtGui import QColor, QCursor
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, \
    QLineEdit, QPushButton, QLabel, QFrame, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView, QComboBox, \
    QScrollArea, QGroupBox, QSpacerItem, QSizePolicy, QAbstractItemView, QFileDialog, QGridLayout, QLayout, QDialog, \
    QTextEdit, QApplication, QToolTip
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QCoreApplication
# import geoip2.database
import pandas as pd
from PyQt5.QtWidgets import QHBoxLayout, QWidgetItem, QLayoutItem
from PyQt5 import QtCore
from PyQt5.QtGui import QFontMetrics

scroll_style = """
    /* 水平滚动条样式 */
    QScrollBar:horizontal {
        border: none;
        background: none;  /* 将背景设置为透明 */
        height: 0;  /* 设置高度为0，完全隐藏 */
    }

    /* 水平滚动条滑块样式 */
    QScrollBar::handle:horizontal {
        background: #c0c0c0;
        min-width: 20px;  /* 设置滑块的最小宽度 */
    }

    /* 水平滚动条增加和减少按钮样式 */
    QScrollBar::add-line:horizontal {
        border: none;
        background: none;
    }

    QScrollBar::sub-line:horizontal {
        border: none;
        background: none;
    }

    /* 垂直滚动条样式 */
    QScrollBar:vertical {
        border: none;
        background: none;  /* 将背景设置为透明 */
        width: 0;  /* 设置宽度为0，完全隐藏 */
    }

    /* 垂直滚动条滑块样式 */
    QScrollBar::handle:vertical {
        background: #c0c0c0;
        min-height: 20px;  /* 设置滑块的最小高度 */
    }

    /* 垂直滚动条增加和减少按钮样式 */
    QScrollBar::add-line:vertical {
        border: none;
        background: none;
    }

    QScrollBar::sub-line:vertical {
        border: none;
        background: none;
    }

    QScrollArea { 
        border: 1px solid #d5deee; 

    }
"""

scroll_style_mainPage = """
    /* 水平滚动条样式 */
    QScrollBar:horizontal {
        border: none;
        background: #f0f0f0;
        height: 10px;  /* 设置滚动条高度 */
        margin: 0px 20px 0 20px;  /* 设置滚动条的边距 */
    }

    /* 水平滚动条滑块样式 */
    QScrollBar::handle:horizontal {
        background: #c0c0c0;
        min-width: 20px;  /* 设置滑块的最小宽度 */
    }

    /* 水平滚动条增加和减少按钮样式 */
    QScrollBar::add-line:horizontal {
        border: none;
        background: none;
    }

    QScrollBar::sub-line:horizontal {
        border: none;
        background: none;
    }

    /* 垂直滚动条样式 */
    QScrollBar:vertical {
        border: none;
        background: #f0f0f0;
        width: 5px;  /* 设置滚动条宽度 */
        margin: 20px 0 20px 0;  /* 设置滚动条的边距 */
    }

    /* 垂直滚动条滑块样式 */
    QScrollBar::handle:vertical {
        background: #c0c0c0;
        min-height: 20px;  /* 设置滑块的最小高度 */
    }

    /* 垂直滚动条增加和减少按钮样式 */
    QScrollBar::add-line:vertical {
        border: none;
        background: none;
    }

    QScrollBar::sub-line:vertical {
        border: none;
        background: none;
        margin-top:25px;
    }
    QScrollArea { border: none;}
"""





class CveDetailPage(QDialog):
    def __init__(self, cve_data, cve):
        super().__init__()
        self.cve = cve
        self.setWindowTitle("CVE详情")
        self.setGeometry(200, 100, 2200, 1200)  # 设置窗口大小
        self.setStyleSheet("background-color: white;")  # 设置背景色为白色
        layout = QVBoxLayout()

        # 显示CVE信息
        self.display_cve_data(cve_data, layout)

        self.setLayout(layout)

    def parse_cve_data(self, cve_data):
        parsed_text = "CVE: " + self.cve + '<br><br>'
        for key, value in cve_data.items():
            if key == "references":
                continue  # references单独处理
            if isinstance(value, list):
                value_str = ", ".join(value)
            else:
                value_str = str(value)
            parsed_text += f"<b>{key}</b>: {value_str}<br>"
            parsed_text += "<br>"  # 这里的<br>标签会添加一个空行，相当于间距为10

        return parsed_text

    def display_cve_data(self, cve_data, layout):
        # 创建一个QGroupBox来容纳CVE信息
        self.cve_group_box = QGroupBox(f"{self.cve} 详情")

        # 创建一个垂直布局以放置标签
        self.cve_layout = QVBoxLayout()

        # 解析并显示CVE信息
        parsed_text = self.parse_cve_data(cve_data)
        cve_label = QLabel()
        # 设置标签可编辑，允许用户通过鼠标选中文本
        cve_label.setTextInteractionFlags(cve_label.textInteractionFlags() | Qt.TextSelectableByMouse)

        cve_label.setTextFormat(Qt.RichText)
        cve_label.setText(parsed_text)
        cve_label.setWordWrap(True)  # 设置为自动换行
        self.cve_layout.addWidget(cve_label)

        # 设置布局到QGroupBox中
        self.cve_group_box.setLayout(self.cve_layout)

        layout.addWidget(self.cve_group_box)

        # 显示参考链接
        if "references" in cve_data:
            self.display_references(cve_data["references"], layout)

    def display_references(self, references, layout):
        # 创建一个QScrollArea来容纳参考链接
        references_scroll_area = QScrollArea()
        references_scroll_area.setWidgetResizable(True)  # 允许小部件自动调整大小以适应视口
        references_scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)  # 只在需要时显示垂直滚动条

        # 创建一个QWidget以放置参考链接
        references_widget = QWidget()
        references_layout = QVBoxLayout(references_widget)

        # 创建标签来显示每个参考链接
        for reference in references:
            reference_label = QLabel(f"<a href=\"{reference}\">{reference}</a>")
            reference_label.setOpenExternalLinks(True)  # 设置为可点击链接
            references_layout.addWidget(reference_label)

        references_widget.setLayout(references_layout)
        references_scroll_area.setWidget(references_widget)

        layout.addWidget(references_scroll_area)


class DetailPage(QWidget):
    def __init__(self, data):
        super().__init__()
        self.data = data  # data 是 data_list 中从所在的开始到结束的一个一个字典数据
        self.initUI()

    def initUI(self):
        self.setGeometry(200, 100, 2200, 1200)  # 设置窗口大小
        self.setStyleSheet("background-color: #f7f8fc;")  # 设置背景色
        font = QFont("Microsoft YaHei", 12)  # 字体和大小
        QApplication.setFont(font)

        main_layout = QVBoxLayout()  # 窗口总布局，后续会horizontal_layout和table_scroll_area两个布局

        horizontal_layout = QHBoxLayout()  # 创建一个水平布局管理器，用于水平排列基本信息和链接信息

        # ---------------基本信息部分
        info_groupbox = QGroupBox()
        info_groupbox.setTitle("基本信息")
        font = QFont()
        font.setPointSize(14)  # 字体大小
        font.setBold(True)  # 字体加粗
        info_groupbox.setFont(font)
        info_groupbox.setStyleSheet(
            "QGroupBox { background-color: #ffffff; border: 1px solid gray; border-radius: 5px;}")

        info_layout = QVBoxLayout()
        info_layout.setContentsMargins(10, 30, 10, 30)  # 设置内边距

        ip_label = QLabel()
        ip_label.setText(f"<img src='icon/ip.png' width='25' height='25'> {self.data['ip']}")
        info_layout.addWidget(ip_label)

        city_label = QLabel()
        city_label.setText(f"<img src='icon/location.png' width='25' height='25'> {self.data['city']}")
        info_layout.addWidget(city_label)

        code_label = QLabel()
        code_label.setText(f"<img src='icon/location.png' width='25' height='25'> {self.data['code']}")
        info_layout.addWidget(code_label)

        # 构建一个字典，其中键是更新时间，值是对应的条目
        port_list = list(self.data.get("ports").keys())
        for port in port_list:
            port_data = self.data["ports"][port]

            from_value = port_data['from']
            latest_update_time = port_data['update_time']
            update_time_label = QLabel()
            update_time_label.setText(f"<img src='icon/update_time.png' width='25' height='25'> {latest_update_time}")
            update_time_label.setToolTip("最新更新时间")  # 悬浮提示信息

        from_label = QLabel()
        from_label.setText(f"<img src='icon/save_from.png' width='25' height='25'> {from_value} ")
        from_label.setToolTip("来源")  # 悬浮提示信息

        info_layout.addWidget(update_time_label)
        info_layout.addWidget(from_label)

        info_groupbox.setLayout(info_layout)

        # --------------------------------------链接信息部分
        link_scroll_area = QScrollArea()
        link_scroll_area.setMaximumHeight(400)
        link_scroll_area.setStyleSheet(scroll_style)
        link_scroll_area.setWidgetResizable(True)  # 设置滚动区域将根据内部控件的大小来调整滚动条的大小，以确保可以滚动查看整个控件

        # 最外面的框
        link_groupbox = QGroupBox()
        link_groupbox.setTitle("Web资产")
        font = QFont()  # 设置标题的字体大小
        font.setBold(True)  # 设置字体加粗
        font.setPointSize(14)
        link_groupbox.setFont(font)
        link_groupbox.setStyleSheet(
            "QGroupBox { background-color: #ffffff; border: 1px solid gray; border-radius: 5px; }")

        # 用来放置 链接/复制按钮/跳转按钮/title
        link_layout = QVBoxLayout()
        link_layout.addSpacing(20)

        links = set()
        for port in port_list:
            port_data = self.data["ports"][port]
            if port_data['pro'] == "http" or port_data['pro'] == "https":
                link = f"{port_data['pro']}://{self.data['ip']}:{port}"
                links.add((link, self.data["ports"][port]['title']))

        for link, title in links:
            # 用来放置 复制按钮/跳转按钮/title
            link_button_layout = QHBoxLayout()
            link_label = QLabel(link)
            link_label.setStyleSheet(
                "QLabel { color: #3449b3; text-decoration: underline; background-color: #ffffff;  }")
            link_button_layout.addWidget(link_label)
            # 跳转按钮
            jump_button = QPushButton()
            jump_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标悬停时的指针形状为手型
            # 设置跳转的图标
            icon = QIcon("icon/access.png")
            jump_button.setIcon(icon)
            # 设置悬浮提示
            jump_button.setToolTip("跳转")
            jump_button.setStyleSheet("border: none;")
            jump_button.clicked.connect(lambda state, l=link: self.open_link(l))
            link_button_layout.addSpacing(20)  # 设置按钮距离上一个组件10px;
            link_button_layout.addWidget(jump_button)

            # 复制按钮
            copy_button = QPushButton()
            copy_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标悬停时的指针形状为手型
            icon = QIcon("icon/copy.png")
            copy_button.setIcon(icon)
            copy_button.setToolTip("复制")
            copy_button.setStyleSheet("border: none;")
            copy_button.clicked.connect(lambda state, _link=link: self.copy_string(_link))
            link_button_layout.addWidget(copy_button)

            # title
            if len(title) > 0:
                title_label = QLabel(title)
                title_label.setStyleSheet("QLabel { color: gray;  background-color: #ffffff;  }")
                link_button_layout.addSpacing(40)  # 设置标题距离按钮40px;
                link_button_layout.addWidget(title_label)

            # 添加弹簧让 跳转/复制/title 靠近链接
            link_button_layout.addStretch()
            link_layout.addLayout(link_button_layout)

        if len(links) < 8:
            link_layout.addStretch()
        link_groupbox.setLayout(link_layout)
        link_scroll_area.setWidget(link_groupbox)

        # ----------------------------- CVE信息
        CVE_groupbox = QGroupBox()
        CVE_groupbox.setTitle("所有CVE信息")
        font = QFont()
        font.setPointSize(14)  # 字体大小
        font.setBold(True)  # 字体加粗
        CVE_groupbox.setFont(font)
        CVE_groupbox.setStyleSheet(
            "QGroupBox {  border: 1px solid gray; border-radius: 5px;}")

        # 产品布局: 创建一个滚动区域
        CVE_scroll_area = QScrollArea()
        CVE_scroll_area.setMaximumHeight(400)
        CVE_scroll_area.setWidgetResizable(True)  # 设置滚动区域大小自适应
        CVE_scroll_area.setStyleSheet(scroll_style)

        product_widget = QWidget()  # 创建一个小部件来包含所有产品按钮
        # vuln_layout.setContentsMargins(10, 30, 10, 30)  # 设置内边距
        # product_widget.setFixedHeight(340)
        product_widget.setStyleSheet("border: none;background-color: transparent;")  # 设置 product_widget 的样式表，移除边框
        vuln_layout = QGridLayout(product_widget)

        cve_list = []
        cve_verify = []
        vulns_data = self.data.get('vulns')
        if vulns_data:
            for key, value in vulns_data.items():
                cve_list.append(key)
                if value.get('verified', True):
                    cve_verify.append(key)
        num_columns = 3  # 每行最多显示的按钮数量
        _row = 0
        _col = 0
        for vuln in cve_list:
            cve_button = QPushButton("", self)  # 去除首尾空格
            cve_button.setCursor(Qt.PointingHandCursor)
            cve_data = self.data["vulns"][vuln]
            cve_button.clicked.connect(lambda _, cve_data=cve_data: self.load_cve_detail_page(cve_data, vuln))
            button_width = 230
            button_height = 30
            cve_button.setFixedSize(button_width, button_height)
            if vuln in cve_verify:
                cve_button.setStyleSheet("background-color: green; color: white;text-align: center;border-radius:10px;")
            else:
                cve_button.setStyleSheet(
                    "background-color: #99badd; color: white;text-align: center;border-radius:10px;")
            cve_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)  # 设置按钮的大小策略为水平方向自适应，垂直方向固定
            # 计算按钮文本的最大宽度
            font_metrics = QFontMetrics(cve_button.font())
            max_button_text_width = button_width - 20  # 例如，假设我们保留了10像素的填充空间
            # 如果文本的宽度超过了按钮文本的最大宽度，则进行截断
            if font_metrics.width(vuln.strip()) > max_button_text_width:
                ellipsis_text = font_metrics.elidedText(vuln.strip(), Qt.ElideRight, max_button_text_width)
            else:
                ellipsis_text = vuln.strip()

            cve_button.setText(ellipsis_text)
            vuln_layout.addWidget(cve_button, _row, _col)
            _col += 1
            if _col == num_columns:
                _col = 0
                _row += 1

        product_widget.setLayout(vuln_layout)
        # 将 product_widget 添加到 CVE_groupbox 中
        CVE_groupbox.setLayout(QVBoxLayout())
        CVE_groupbox.layout().addWidget(product_widget)

        # 将 CVE_groupbox 添加到滚动区域中
        CVE_scroll_area.setWidget(CVE_groupbox)

        # 将基本信息和链接信息添加到水平布局中
        horizontal_layout.addWidget(info_groupbox, 1)
        horizontal_layout.addWidget(CVE_scroll_area, 2)
        horizontal_layout.addWidget(link_scroll_area, 2)
        # 将水平布局添加到主布局中
        main_layout.addLayout(horizontal_layout)

        # ----------------------------------------表格部分
        table_scroll_area = QScrollArea()
        table_scroll_area.setWidgetResizable(True)  # 设置滚动区域将根据内部控件的大小来调整滚动条的大小，以确保可以滚动查看整个控件
        table_scroll_area.setStyleSheet(scroll_style)

        ip_table = QTableWidget()
        ip_table.setAlternatingRowColors(True)  ## 启用交替行的背景色
        ip_table.setStyleSheet("QTableView { alternate-background-color: #FFFFFF;border:none;}")  ## 设置交替行的背景颜色为白色
        ip_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置表格控件不可编辑

        # 设置表格的列宽自适应同时设置可以手动拖拽改变列宽
        ip_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        ip_table.horizontalHeader().setStretchLastSection(True)

        ip_table.horizontalHeader().setStyleSheet(
            "QHeaderView::section { background-color: #464953; color: white}")  # 设置表头背景色等 464953

        ip_table.setRowCount(0)
        ip_table.setColumnCount(5)
        ip_table.setHorizontalHeaderLabels(["协议", "端口", "产品", "标题", "来源: 更新时间"])
        # 隐藏垂直标头，即行号
        # ip_table.verticalHeader().setVisible(False)

        merged_data = {}
        port_data = self.data["ports"]
        for port in port_data:
            key = (port_data[port]["pro"], port, port_data[port]["product"], port_data[port]["title"])
            if key in merged_data:
                merged_data[key].append(f"{port_data[port]['from']}: {port_data[port]['update_time']}")
            else:
                merged_data[key] = [f"{port_data[port]['from']}: {port_data[port]['update_time']}"]

        for key, value in merged_data.items():
            row = ip_table.rowCount()
            ip_table.insertRow(row)
            # 协议
            pruduct_item = QTableWidgetItem((key[2]))
            pruduct_item.setToolTip((key[2]))
            # 端口
            title_item = QTableWidgetItem(key[3])
            title_item.setToolTip(key[3])

            ip_table.setItem(row, 0, QTableWidgetItem(key[0]))
            ip_table.setItem(row, 1, QTableWidgetItem(str(key[1])))
            ip_table.setItem(row, 2, pruduct_item)
            ip_table.setItem(row, 3, title_item)
            ip_table.setItem(row, 4, QTableWidgetItem(", ".join(value)))

        table_scroll_area.setWidget(ip_table)
        main_layout.addWidget(table_scroll_area)

        self.setLayout(main_layout)
        self.setWindowTitle('详细信息')

    def load_cve_detail_page(self, cve_data, vuln):
        self.show_detail_page(cve_data, vuln)

    def show_detail_page(self, cve_detail_info, cve):
        detail_page = CveDetailPage(cve_detail_info, cve)
        detail_page.exec_()

    def open_link(self, link):
        webbrowser.open_new_tab(link)

    def copy_string(self, link):
        clipboard = QApplication.clipboard()
        clipboard.setText(link)
        QMessageBox.information(None, "提示", "已复制")



class DataDisplay(QWidget):
    def __init__(self, data_list):
        super().__init__()
        icon = QIcon("icon/search.png")
        self.setWindowIcon(icon)

        self.tmp_port_table = {}
        self.tmp_protocol_table = {}
        self.tmp_vuln_table = {}
        self.tmp_cve_verify_table = {}
        self.tmp_product_table = {}
        self.tmp_city_table = {}
        self.tmp_ipc_table = {}  # ip c段
        self.product_bt_min_width = 180 # 产品按钮最小宽度
        self.proportion = 2 # 端口信息区域对比右侧的ip信息区域的占比

        self.data_list = data_list  # 原始数据

        self.detail_windows = []  # 存储打开的详情窗口对象

        self.search_data_Table = {}  # 搜索的结果总表

        # 创建多个hashtable,用于后续快捷查询
        self.Summary_Table = {}  # 总表
        self.Port_Table = {}
        self.Protocol_Table = {}
        self.Vuln_Table = {}
        self.CVE_Verify_Table = {}  # 验证过有漏洞的
        self.Product_Table = {}
        self.City_Table = {}
        self.IPC_Table = {}

        self.resizeEvent(None)

        for ip_data_dict in data_list:
            # 更新总表
            ip_address = ip_data_dict.get("ip")
            if ip_address and ip_address not in self.Summary_Table:
                self.Summary_Table[ip_address] = ip_data_dict  # 使用 IP 地址作为字典的键，当前字典数据作为值
            # 更新端口表
            port_info_dict = ip_data_dict.get("ports", {})
            if port_info_dict:
                for port, _ in port_info_dict.items():
                    self.Port_Table.setdefault(port, []).append(
                        ip_address)  # setdefault()方法可以实现如果字典中不存在某个键，则设置该键的默认值，然后返回该键对应的值。如果该键已经存在，则直接返回该键对应的值。避免手动检查键是否存在，简化代码
                    # 更新协议表
                    port_info = port_info_dict.get(port, {})
                    if port_info:
                        pro = port_info.get("pro")
                        if pro:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.Protocol_Table.setdefault(pro, []):
                                self.Protocol_Table[pro].append(ip_address)
                    # 更新product表
                    product = port_info.get("product")
                    if product:
                        product_list = str(product).split(",")
                        for product in product_list:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.Product_Table.setdefault(product, []):
                                self.Product_Table[product].append(ip_address)

            # 更新vuln表
            vulns_info_dict = ip_data_dict.get("vulns", {})
            if vulns_info_dict:
                for vuln, _ in vulns_info_dict.items():
                    self.Vuln_Table.setdefault(vuln, []).append(ip_address)
                    try:
                        if _.get("verified") is True:
                            self.CVE_Verify_Table.setdefault(vuln, []).append(ip_address)
                    except:
                        traceback.print_exc()
                        print('+++++++ ', vuln, ip_data_dict.get('ip'))
            # 更新city表
            city = ip_data_dict.get("city")
            if city:
                self.City_Table.setdefault(city, []).append(ip_address)

            # 更新IPC表
            ip = ip_data_dict.get("ip")
            if ip:
                ipc = ".".join(ip.split(".")[:3]) + ".0/24"  # 取 IP 的 C 段
                if ipc:
                    self.IPC_Table.setdefault(ipc, []).append(
                        ip)  # setdefault()方法可以实现如果字典中不存在某个键，则设置该键的默认值，然后返回该键对应的值。如果该键已经存在，则直接返回该键对应的值。避免手动检查键是否存在，简化代码
        # 页码
        self.page_index = 0
        self.items_per_page = 5
        self.current_page = 1

        self.initUI()


    def resizeEvent(self, event):
        current_width = self.width()
        current_height = self.height()
        print(current_height, current_width)

        if current_width * current_height <= 1920*1080:
            self.proportion = 3
            self.product_bt_min_width = 160
        else:   # 分辨率大于2k
            self.proportion = 3
            self.product_bt_min_width = 260
        self.update()


    # ---------------解析搜索语法
    # 解析条件字符串
    def parse_condition(self, condition_str):
        tokens = [token.strip() for token in re.findall(r'\(|\)|\|\||&&|[^|&()]+', condition_str) if
                      token.strip()]   # print(tokens)  # ['city:"美国"', '&&', 'title:"login"', '&&', 'port:"2443"']
        print("******", tokens)
        return self.parse_logical_or(tokens)


    # 解析逻辑或运算符
    def parse_logical_or(self, tokens):
        # 解析左操作数
        left_operand = self.parse_logical_and(tokens)
        # 如果 tokens 不为空且下一个 token 是 '||'
        if tokens and tokens[0] == '||':
            tokens.pop(0)  # 弹出'||'
            # 解析'&&'的右操作数
            right_operand = self.parse_logical_or(tokens)
            # 返回包含逻辑运算符 '||' 和左右操作数的结果的字典
            return {'operator': '||', 'operands': [left_operand, right_operand]}
        # 如果没有 '||'，直接返回左操作数
        return left_operand

    # 解析逻辑与运算符
    def parse_logical_and(self, tokens):
        left_operand = self.parse_primary(tokens)
        # 如果 token 不为空且下一个 token 是 '&&'
        if tokens and tokens[0] == '&&':
            tokens.pop(0)  # 弹出'&&'
            # 解析'&&'的右操作数
            right_operand = self.parse_logical_and(tokens)
            # 返回包含逻辑运算符 '&&' 和左右操作数的结果的字典
            return {'operator': '&&', 'operands': [left_operand, right_operand]}
        # 如果没有 '&&'，直接返回左操作数
        return left_operand

    # 解析基本条件
    def parse_primary(self, tokens):
        token = tokens.pop(0)
        # 如果是 '('，则是一个子表达式
        if token == '(':
            expression = self.parse_logical_or(tokens)
            # 确保括号匹配
            if tokens.pop(0) != ')':
                print('[-] error: Mismatched parentheses')
                return
            return expression
        # 如果不是括号，则是一个操作数，直接返回
        return {'value': token}

    # 从指定表中获取满足条件的ip列表
    def search_get_ip_list(self, field, search_value):
        matching_ip_addresses = []
        if field == "city":
            for city, ip_address in self.City_Table.items():
                if city == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
        if field == "ipc":
            for ipc, ip_address in self.IPC_Table.items():
                if ipc == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
        if field == "product":
            for product, ip_address in self.Product_Table.items():
                if product == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
        if field == "vulns":
            for vuln, ip_address in self.Vuln_Table.items():
                if vuln == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
        if field == "pro":
            for pro, ip_address in self.Protocol_Table.items():
                if pro == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
        if field == "port":
            for pro, ip_address in self.Port_Table.items():
                if pro == search_value.strip("\"\"") and ip_address:
                    matching_ip_addresses.extend(ip_address)
                    break
        if field == "cve_verify":
            for cve, value in self.CVE_Verify_Table.items():
                if cve == search_value.strip("\"\"") and value:
                    matching_ip_addresses.extend(value)
        if field == "ip":
            for ip, value in self.Summary_Table.items():
                if ip == search_value.strip("\"\"") and value:
                    matching_ip_addresses.append(ip)
        return matching_ip_addresses

    # 检查单个条件是否满足
    def check_condition(self, condition):
        print("check_condition:", condition)
        if not condition:
            return
        if 'value' in condition:
            try:
                field, value = re.split(r':', condition['value'])
            except:
                QMessageBox.critical(None, "错误", f'搜索条件错误，正确条件如: port:"443"')
                return
        elif 'value1' in condition:
            try:
                field, value = re.split(r':', condition['value1'])
            except:
                QMessageBox.critical(None, "错误", f'搜索条件错误，正确条件如: port:"443"')
                return
            if 'value2' in condition:
                field, value = re.split(r':', condition['value2'])
        elif 'operator' in condition:
            if condition['operator'] == '&&':
                # 获取第一个函数调用的结果作为基准
                base_result = set(self.check_condition(condition['operands'][0]))
                # 逐个遍历后续函数调用的结果，使用 &= 操作符计算交集
                for operand in condition['operands'][1:]:
                    base_result &= set(self.check_condition(operand))
                # 将交集结果转换为列表
                matching_ip_addresses = list(base_result)
                return matching_ip_addresses

            elif condition['operator'] == '||':
                # 获取每次函数调用的结果
                results = [self.check_condition(operand) for operand in condition['operands']]
                # 将结果合并成一个列表
                combined_results = []
                if results:
                    for result in results:
                        if result:
                            combined_results.extend(result)
                    # 去除重复值，并将集合转换为列表
                    unique_results = list(set(combined_results))
                    return unique_results
                else:
                    return []
            else:
                return []
        else:
            return False
        return self.search_get_ip_list(field, value)

    # 获取满足条件的数据
    def get_filtered_data(self, condition_structure):
        self.filtered_data = {}
        ip_address_list = self.check_condition(condition_structure)
        if ip_address_list:
            for ip in ip_address_list:
                self.filtered_data[ip] = (self.Summary_Table[ip])
        return self.filtered_data

    # -------------------------------------
    def export_data(self, ):
        text = self.search_input.text()
        if text:
            data = self.search_data_Table
        else:
            data = self.Summary_Table
        current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"data_{current_time}.json"
        with open(filename, 'w', encoding='utf-8', errors='ignore') as f:
            f.write(json.dumps(data))
        QMessageBox.information(None, "提示", f"数据已保存到{filename} 文件中。")

        # # 获取所有键，作为表头
        # headers = data[0].keys()
        # current_time = datetime.now().strftime("%Y%m%d_%H%M%S")
        # filename = f"data_{current_time}.csv"
        # # 将数据写入到 CSV 文件
        # with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        #     writer = csv.DictWriter(csvfile, fieldnames=headers)
        #     # 写入表头
        #     writer.writeheader()
        #     # 写入数据
        #     for data in data:
        #         writer.writerow(data)
        # QMessageBox.information(None, "提示", f"数据已成功写入到{filename} 文件中。")

    # def deal_with_data(self, data):
    #     for dic in data:
    #         if dic.get('Service'):
    #             if dic['Service'] == 'http' or dic['Service'] == 'https':
    #                 dic['title'] = extract_title_from_http_response(dic['Response'])
    #             else:
    #                 dic['title'] = ''
    #         else:
    #             dic['title'] = ''
    #
    #         dic['host'] = dic['URL']
    #         dic['port'] = dic['Port']
    #         dic['pro'] = dic['Service'] if dic.get('Service') else 'unknow'
    #         dic['ip'] = dic['IP']
    #         dic['product'] = dic['FingerPrint'].replace('\t', ',') if dic.get('FingerPrint') else 'unknow,'
    #         area_code = 'N/A'
    #         country = 'N/A'
    #         try:
    #             response = geoip_reader.country(dic['IP'])
    #             area_code = response.country.iso_code
    #             country = response.country.name
    #         except:
    #             pass
    #         dic['city'] = country
    #         dic['code'] = area_code
    #         dic['update_time'] = now_time
    #         dic['from'] = 'kscan'
    #     return data

    def read_data_from_file(self, fileName):
        _, extension = os.path.splitext(fileName)
        if extension.lower() == '.csv':
            return self.read_data_from_csv(fileName)
        elif extension.lower() in ('.xlsx', '.xls'):
            return self.read_data_from_xlsx(fileName)
        elif extension.lower() in ('.json'):
            return self.read_data_from_json(fileName)
        else:
            raise ValueError("不支持的文件格式")

    def read_data_from_xlsx(self, fileName):
        data_list = []
        try:
            df = pd.read_excel(fileName, engine='openpyxl')
            # header = list(df.columns)
            for index, row in df.iterrows():
                row_dict = row.apply(lambda x: str(x))  # 将所有值转换为字符串
                row_dict = row_dict.to_dict()
                data_list.append(row_dict)
            return data_list
        except Exception as e:
            raise ValueError(f"无法读取XLSX文件: {str(e)}")

    def read_data_from_csv(self, fileName):
        data_list = []
        with open(fileName, 'r', newline='', encoding='utf-8') as csvfile:
            reader = csv.DictReader(csvfile)
            # header = reader.fieldnames  # 获取表头的字段名称列表
            for row in reader:
                data_list.append(row)
        return data_list

    def read_data_from_json(self, fileName):
        j_data = None
        with open(fileName, 'r', encoding='utf-8', errors='ignore') as f:
            j_data = json.load(f)
        res = []
        for i in j_data:
            res.append(j_data[i])
        return res

    def update_data(self):
        for ip_data_dict in self.data_list:
            # 更新总表
            ip_address = ip_data_dict.get("ip")
            if ip_address and ip_address not in self.Summary_Table:
                self.Summary_Table[ip_address] = ip_data_dict  # 使用 IP 地址作为字典的键，当前字典数据作为值
            # 更新端口表
            port_info_dict = ip_data_dict.get("ports", {})
            if port_info_dict:
                for port, _ in port_info_dict.items():
                    self.Port_Table.setdefault(port, []).append(
                        ip_address)  # setdefault()方法可以实现如果字典中不存在某个键，则设置该键的默认值，然后返回该键对应的值。如果该键已经存在，则直接返回该键对应的值。避免手动检查键是否存在，简化代码
                    # 更新协议表
                    port_info = port_info_dict.get(port, {})
                    if port_info:
                        pro = port_info.get("pro")
                        if pro:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.Protocol_Table.setdefault(pro, []):
                                self.Protocol_Table[pro].append(ip_address)
                    # 更新product表
                    product = port_info.get("product")
                    if product:
                        product_list = str(product).split(",")
                        for product in product_list:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.Product_Table.setdefault(product, []):
                                self.Product_Table[product].append(ip_address)

            # 更新vuln表
            vulns_info_dict = ip_data_dict.get("vulns", {})
            if vulns_info_dict:
                for vuln, _ in vulns_info_dict.items():
                    self.Vuln_Table.setdefault(vuln, []).append(ip_address)
                    try:
                        if _.get("verified") is True:
                            self.CVE_Verify_Table.setdefault(vuln, []).append(ip_address)
                    except:
                        traceback.print_exc()
                        print('+++++++ ', vuln, ip_data_dict.get('ip'))
            # 更新city表
            city = ip_data_dict.get("city")
            if city:
                self.City_Table.setdefault(city, []).append(ip_address)

            # 更新IPC表
            ip = ip_data_dict.get("ip")
            if ip:
                ipc = ".".join(ip.split(".")[:3]) + ".0/24"  # 取 IP 的 C 段
                if ipc:
                    self.IPC_Table.setdefault(ipc, []).append(
                        ip)

    def import_data(self, ):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "选择文件", "", "All Files (*)", options=options)
        if fileName:
            try:
                data_list = self.read_data_from_file(fileName)
                QMessageBox.information(self, "提示", "文件读取成功！", QMessageBox.Ok)
                # self.table_header = header
                # self.data_list = self.deal_with_data(data_list) # 这里是kscan的处理
                print(data_list)
                self.data_list = data_list
                self.search_data_Table = {}
                self.update_data()
                self.search_data(init=True)
            except Exception as e:
                traceback.print_exc()
                QMessageBox.critical(self, "错误", str(e))

    def get_count_field(self, has_search, model):
        lengths = {}
        if not has_search:
            if model == "ipc":
                for ipc, ip_addresses in self.IPC_Table.items():
                    lengths[ipc] = len(ip_addresses)
            if model == "vulns":
                for vuln, ip_addresses in self.Vuln_Table.items():
                    lengths[vuln] = len(ip_addresses)
            if model == "city":
                for ciry, ip_addresses in self.City_Table.items():
                    lengths[ciry] = len(ip_addresses)
            if model == "port":
                for port, ip_addresses in self.Port_Table.items():
                    lengths[port] = len(ip_addresses)
            if model == "product":
                for product, ip_addresses in self.Product_Table.items():
                    lengths[product] = len(ip_addresses)
            if model == "pro":
                for pro, ip_addresses in self.Protocol_Table.items():
                    lengths[pro] = len(ip_addresses)
            if model == "cve_verify":
                for cve, ip_addresses in self.CVE_Verify_Table.items():
                    lengths[cve] = len(ip_addresses)
        else:
            if model == "ipc":
                for ipc, ip_addresses in self.tmp_ipc_table.items():
                    lengths[ipc] = len(ip_addresses)
            if model == "vulns":
                for vuln, ip_addresses in self.tmp_vuln_table.items():
                    lengths[vuln] = len(ip_addresses)
            if model == "city":
                for ciry, ip_addresses in self.tmp_city_table.items():
                    lengths[ciry] = len(ip_addresses)
            if model == "port":
                for port, ip_addresses in self.tmp_port_table.items():
                    lengths[port] = len(ip_addresses)
            if model == "product":
                for product, ip_addresses in self.tmp_product_table.items():
                    lengths[product] = len(ip_addresses)
            if model == "pro":
                for pro, ip_addresses in self.tmp_protocol_table.items():
                    lengths[pro] = len(ip_addresses)
            if model == "cve_verify":
                for cve, ip_addresses in self.tmp_cve_verify_table.items():
                    lengths[cve] = len(ip_addresses)

        # 对键和值进行排序
        sorted_field_counts = dict(sorted(lengths.items(), key=lambda item: item[1], reverse=True))
        return sorted_field_counts

    def display_info_clicked(self, field_name):
        button = self.sender()
        value = button.objectName().strip()
        field_name = field_name.lower()

        search_data = field_name + ":" + value

        text = self.search_input.text()
        if text:
            condition_str = text + " && " + search_data
        else:
            condition_str = search_data
        self.search_input.setText(condition_str)
        self.search_data()

    def initUI(self):
        # 获取屏幕尺寸
        desktop = QApplication.desktop()
        rect = desktop.availableGeometry()
        width = rect.width()
        height = rect.height()
        self.setGeometry(0, 0, width, height)

        self.setStyleSheet("background-color: #f2f7ff;")  # 设置背景色
        font = QFont("Microsoft YaHei", 12)  # 字体和大小
        QApplication.setFont(font)

        self.main_layout = QVBoxLayout()
        self.top_layout = QVBoxLayout()
        self.bottom_layout = QHBoxLayout()
        self.left_layout = QVBoxLayout()
        # 右侧
        self.right_display_layout = QVBoxLayout()

        self.null_layout = QHBoxLayout()

        # 创建一个带有白色背景的 QWidget
        self.background_widget = QWidget(self)
        self.background_widget.setStyleSheet("background-color: white;")
        self.right_layout = QVBoxLayout(self.background_widget)
        # self.right_layout = QVBoxLayout()
        self.right_layout.setContentsMargins(0, 0, 0, 0)

        self.main_layout.addLayout(self.top_layout)
        self.main_layout.addLayout(self.bottom_layout)
        self.setLayout(self.main_layout)
        self.setWindowTitle('被动信息收集')
        self.init_left_page()
        self.init_right_page()


    def clear_left_layout(self, ):
        # 清除旧的左侧布局内容
        for i in reversed(
                range(
                    self.left_layout.count())):  # 使用reversed用于从 self.left_layout.count() - 1 开始向 0 反向遍历。这意味着它会从最后一个子项开始，逐步向前遍历直到第一个子项。
            # for i in range(self.left_layout.count()) 会从 0 开始逐个遍历到 self.left_layout.count() - 1。这意味着它会从第一个子项开始，依次遍历到最后一个子项。
            # 使用 reversed(range(self.left_layout.count())) 来确保在删除子项时，不会影响到后续的遍历。因为删除一个子项可能会影响到布局中其他子项的索引顺序，所以从最后一个子项开始删除更为安全。
            item = self.left_layout.itemAt(i)
            if isinstance(item, QWidgetItem):
                widget = item.widget()
                if widget is not None:
                    widget.setParent(None)
            elif isinstance(item, QLayoutItem):
                layout = item.layout()
                if layout is not None:
                    layout.deleteLater()

    def init_left_page(self, search_data=False):
        self.clear_left_layout()

        # 统计数据
        fields = ['city', 'pro', 'product', 'vulns', "port", "ipc", "cve_verify"]
        for field in fields:
            field_groupbox = QGroupBox()
            field_groupbox.setStyleSheet(
                "QGroupBox { background-color: #f2f7ff; font-size:18px; color: #4778c7;font-weight: bold;border:none}"
                "QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding-left: 10px; }")
            field_layout = QVBoxLayout()
            title_text = field
            if field == 'vulns':
                title_label = QLabel(f"CVE 排名")
            else:
                title_label = QLabel(f"{field} 排名")

            field_counts = self.get_count_field(search_data, model=field)

            title_label.setStyleSheet(
                "font-size: 22px; color: #4b5488;")
            title_layout = QHBoxLayout()
            title_layout.addWidget(title_label)
            field_groupbox.setLayout(field_layout)

            for value, count in field_counts.items():
                value = str(value).strip(";")
                row_layout = QHBoxLayout()  # 垂直布局来对齐标签和数量
                value = value.replace("&", "&&")
                value_button = QPushButton(f"    {value}", objectName=value)
                font = QFont("Microsoft YaHei", 12)
                value_button.setFont(font)
                value_button.setStyleSheet(
                    "text-align: left; border: none; color: #7e8e9e; background-color: transparent;font-size: 20px; ")
                value_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标指针为手型
                value_button.clicked.connect(lambda _, title_value=title_text: self.display_info_clicked(title_value))
                row_layout.addWidget(value_button)
                row_layout.addStretch()

                count_button = QPushButton(f"{count}", objectName=value)
                count_button.setStyleSheet(
                    "text-align: left; border: none; color: gray; background-color: transparent;font-size: 22px;")
                count_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标指针为手型
                count_button.clicked.connect(lambda _, title_value=title_text: self.display_info_clicked(title_value))
                row_layout.addWidget(count_button)
                field_layout.addLayout(row_layout)

            # 创建滚动区域并将统计块的布局放置在其中
            left_scroll_area = QScrollArea()
            left_scroll_area.setStyleSheet(scroll_style)

            left_scroll_area.setMinimumHeight(120)
            left_scroll_area.setWidget(field_groupbox)
            left_scroll_area.setWidgetResizable(True)  # 设置滚动区域的部件可调整大小
            # 把滚动条添加到左侧
            self.left_layout.addLayout(title_layout)
            self.left_layout.addWidget(left_scroll_area)

    def init_right_page(self):
        search_layout = QHBoxLayout()
        search_label = QLabel("搜索语句:")
        # 使用样式表设置字体为微软雅黑
        search_label.setStyleSheet("QLabel { font-family: Microsoft YaHei;font-weight:bold; color: #4778c7}")
        self.search_input = QLineEdit()
        self.search_input.setFixedWidth(1200)  # 设置按钮宽度
        self.search_input.returnPressed.connect(self.search_data)  # 绑定回车
        self.search_input.setStyleSheet("border-radius: 8px;height: 40px;border: 2px solid #3d8fde;")
        search_button = QPushButton("")
        search_button.setFixedWidth(100)  # 设置按钮宽度
        search_button.setStyleSheet(
            "text-align: center; color: #ffffff; background-color: #4778c7;border-radius: 5px;height: 38px;width:80px;")
        icon = QIcon("icon/search-2.png")
        search_button.setIcon(icon)
        search_button.clicked.connect(self.search_data)

        search_layout.addStretch()
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_button)
        search_layout.addStretch()
        # 把搜索按钮等添加到上半部
        self.top_layout.addLayout(search_layout)
        self.main_layout.addLayout(self.top_layout)

        self.mainPage_scroll_area = QScrollArea()
        self.mainPage_scroll_area.setWidgetResizable(True)
        self.mainPage_scroll_area.setStyleSheet(scroll_style_mainPage)

        self.data_layout = QVBoxLayout()

        # 展示数据
        self.right_display_data()

        data_widget = QWidget()
        data_widget.setStyleSheet("border: none;")  # 设置每块显示界面的边框
        data_widget.setLayout(self.data_layout)
        self.mainPage_scroll_area.setWidget(data_widget)

        self.right_layout.addWidget(self.mainPage_scroll_area)

        pagination_layout = QHBoxLayout()
        self.export_button = QPushButton("导出")
        self.export_button.setStyleSheet(
            "QPushButton { background-color: #4778c7; border-radius: 10px; color: white; height:30px;width:100px;}")
        self.export_button.clicked.connect(self.export_data)
        pagination_layout = QHBoxLayout()
        self.import_button = QPushButton("导入")
        self.import_button.setStyleSheet(
            "QPushButton { background-color: #4778c7; border-radius: 10px; color: white; height:30px;width:100px;}")
        self.import_button.clicked.connect(self.import_data)

        pagination_layout.addWidget(self.export_button)
        pagination_layout.addWidget(self.import_button)
        pagination_layout.addStretch()

        total_pages, total = self.get_totle_pages()

        self.count_label = QLabel(
            f"共{total}条数据，共{total_pages}页,当前第{self.current_page}页")
        pagination_layout.addWidget(self.count_label)

        self.prev_button = QPushButton("上一页")
        self.prev_button.setStyleSheet(
            "QPushButton { background-color: #4778c7; border-radius: 10px; color: white; height:30px;width:100px;}")
        self.prev_button.clicked.connect(self.prev_page)
        pagination_layout.addWidget(self.prev_button)

        self.next_button = QPushButton("下一页")
        self.next_button.setStyleSheet(
            "QPushButton { background-color: #4778c7; border-radius: 10px; color: white; height:30px;width:100px;}")
        self.next_button.clicked.connect(self.next_page)
        pagination_layout.addWidget(self.next_button)

        self.page_input = QLineEdit()
        self.page_input.setFixedWidth(120)  # 设置按钮宽度
        self.page_input.setStyleSheet("border-radius: 8px;height: 35px;border: 1px solid #3d8fde;")
        pagination_layout.addWidget(self.page_input)

        self.go_button = QPushButton("跳转")
        self.go_button.setStyleSheet(
            "QPushButton { background-color: #4778c7; border-radius: 10px; color: white; height:30px;width:100px;}")
        self.go_button.clicked.connect(self.go_to_page)
        pagination_layout.addWidget(self.go_button)

        self.page_number_tips = QLabel("每页显示")
        self.items_per_page_combo = QComboBox()
        combo_box_style = """
                        QComboBox {
                            border: 1px solid gray;
                            border-radius: 10px;
                            padding: 1px 10px 1px 1px;
                            min-width: 2em;
                            background-color: white;
                            height: 35px;
                        }
                        QComboBox::down-arrow {
                            image: url(icon/down.png);  /* 替换为您想要的箭头图标路径 */
                            height: 35px;
                        }
                        QComboBox::drop-down {
                            border: none;  /* 设置下拉按钮无边框 */
                        }
                    """
        self.items_per_page_combo.setStyleSheet(combo_box_style)
        self.items_per_page_combo.addItems(["5", "10", "20", "50", "100", "500", "1000", "5000", "10000"])
        self.items_per_page_combo.setCurrentIndex(0)
        self.items_per_page_combo.currentIndexChanged.connect(self.change_items_per_page)
        self.tips = QLabel("条")
        pagination_layout.addWidget(self.page_number_tips)
        pagination_layout.addWidget(self.items_per_page_combo)
        pagination_layout.addWidget(self.tips)

        self.right_layout.addLayout(pagination_layout)

        self.bottom_layout.addLayout(self.left_layout, 2)  # 左侧布局占据1/5的空间

        self.right_display_layout.addLayout(self.null_layout, 1)
        self.right_display_layout.addWidget(self.background_widget, 50)

        self.bottom_layout.addLayout(self.right_display_layout, 9)  # 右侧布局占据4/5的空间

        self.main_layout.addLayout(self.bottom_layout)
        self.setLayout(self.main_layout)
        self.setWindowTitle('百川 · 数据检索')

    def open_link(self, link):
        webbrowser.open_new_tab(link)

    def copy_string(self, link):
        clipboard = QApplication.clipboard()
        clipboard.setText(link)
        QMessageBox.information(None, "提示", "已复制")

    def get_ports_pros_updateTime_for_ip(self, ip):
        ports_pros_updatTime_product = []
        _data = {}
        for data in self.data_list:
            if data['ip'] == ip:
                port_list = list(data["ports"].keys())
                for port in port_list:
                    port_data = data["ports"][port]
                    _data["port"] = port
                    _data["pro"] = port_data["pro"]
                    _data["update_time"] = port_data["update_time"]
                    _data["product"] = port_data["product"]
                    ports_pros_updatTime_product.append(str(_data))
        return ports_pros_updatTime_product

    def port_button_clicked(self, clicked_port):
        text = self.search_input.text()
        if text:
            condition_str = text + " && " + f"port:\"{clicked_port}\""
        else:
            condition_str = f"port:\"{clicked_port}\""
        self.search_input.setText(condition_str)
        self.search_data()

    def search_product(self, product):

        text = self.search_input.text()
        if text:
            condition_str = text + " && " + f'product:"{product}"'
        else:
            condition_str = f'product:"{product}"'
        self.search_input.setText(condition_str)

        self.search_data()

    def get_IP_values_by_range(self, start_index=None, end_index=None):
        # 获取字典的键，并根据给定的索引范围进行过滤
        keys = list(self.Summary_Table.keys())
        if start_index is not None and end_index is not None:
            keys = keys[start_index:end_index]
        elif start_index is not None:
            keys = keys[start_index:]
        elif end_index is not None:
            keys = keys[:end_index]
        return keys

    def search_get_IP_values_by_range(self, start_index=None, end_index=None):
        # 获取字典的键，并根据给定的索引范围进行过滤
        keys = list(self.search_data_Table.keys())
        if start_index is not None and end_index is not None:
            keys = keys[start_index:end_index]
        elif start_index is not None:
            keys = keys[start_index:]
        elif end_index is not None:
            keys = keys[:end_index]
        return keys

    def right_display_data(self):
        start = self.page_index * self.items_per_page
        end = start + self.items_per_page
        if self.search_data_Table:
            ip_list_data = self.search_get_IP_values_by_range(start, end)
        else:
            if self.search_input.text().strip() == "":
                ip_list_data = self.get_IP_values_by_range(start, end)
            else:
                ip_list_data = {}

        for ip in ip_list_data:
            if self.search_data_Table:
                data = self.search_data_Table[ip]
            else:
                data = self.Summary_Table[ip]

            block_layout = QVBoxLayout()
            block_layout.setSpacing(10)  # 控件之间设置10px间距
            # 添加边框
            block_frame = QFrame()
            block_frame.setFrameShape(QFrame.Box)
            block_frame.setLayout(block_layout)

            # 头部分
            header_layout = QHBoxLayout()
            ip_label = QLabel(data['ip'])

            if self.CVE_Verify_Table:
                for value_list in self.CVE_Verify_Table.values():
                    if data['ip'] in value_list:
                        ip_label.setStyleSheet("color: red;")
            ip_label.setFont(QFont("Microsoft YaHei", 18))
            header_layout.addWidget(ip_label)

            # 复制按钮
            copy_button = QPushButton()
            # 设置按钮图标
            icon = QIcon("icon/copy.png")
            copy_button.setIcon(icon)
            copy_button.setToolTip("复制")
            copy_button.setStyleSheet("border: none;")
            link_ip = data["ip"]
            copy_button.clicked.connect(lambda _, link=link_ip: self.copy_string(link))
            header_layout.addWidget(copy_button)

            spacer = QSpacerItem(120, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
            header_layout.addItem(spacer)  # 添加长为120,宽为20的空白，让详情按钮靠右展示

            # 详情按钮
            detail_button = QPushButton(" 详情")
            detail_button.setCursor(Qt.PointingHandCursor)  # 设置悬浮为手型
            icon = QIcon("icon/detail.png")
            detail_button.setIcon(icon)
            detail_button.setFixedWidth(120)  # 设置按钮宽度
            detail_button.setStyleSheet("background-color: #99badd; color: white;border-radius: 8px;height: 35px;")
            ip_data_dict = self.Summary_Table[data['ip']]
            detail_button.clicked.connect(lambda _, data=ip_data_dict: self.show_detail(data))
            header_layout.addWidget(detail_button)
            block_layout.addLayout(header_layout)
            # -------------------------------------------------------布局设置
            all_info_layout = QHBoxLayout()
            info_layout = QVBoxLayout()
            info_widget = QWidget()
            info_widget.setLayout(info_layout)  # 将 QVBoxLayout 设置为 QWidget 的布局
            info_widget.setStyleSheet("background-color: white;")  # 设置 QWidget 的背景色为蓝色
            info_widget.setMinimumHeight(240)

            pro_port_layout = QVBoxLayout()
            pro_port_widget = QWidget()  
            pro_port_widget.setLayout(pro_port_layout)  
            pro_port_widget.setStyleSheet("background-color: white;")  

            # 设置右侧ip信息栏与端口信息栏的布局显示比例
            all_info_layout.addWidget(pro_port_widget, self.proportion)  # 将包含 pro_port_layout 的 QWidget 添加到 all_info_layout 中
            all_info_layout.addWidget(info_widget, 1)  # 将包含 info_layout 的 QWidget 添加到 all_info_layout 中

            # -----------------------------------------------------------
            city_code_layout = QHBoxLayout()
            other_layout = QVBoxLayout()

            # 创建一个水平布局用于放置端口和协议
            self.port_info_layout = QVBoxLayout()

            for key in ["city", "code", "vulns", "port", "domain", "org", "isp", "os", "server"]:
                if key == "port":
                    ports_pros_updatTimes_products = self.get_ports_pros_updateTime_for_ip(data['ip'])
                    self.max_len = 4

                    # 创建一个可滚动的区域，用于后续展示端口和协议
                    scroll_area = QScrollArea()
                    scroll_area.setStyleSheet(scroll_style)
                    scroll_area.setWidgetResizable(True)  # 设置滚动区域将根据内部控件的大小来调整滚动条的大小，以确保可以滚动查看整个控件
                    scroll_area.setMinimumHeight(300)  # 设置滚动区域的最小高度为200像素
                    # 创建表格
                    port_info_table = QTableWidget()
                    port_info_table.setShowGrid(False)  # 不显示网格线
                    port_info_table.setAlternatingRowColors(True)  ## 启用交替行的背景色
                    port_info_table.setStyleSheet(
                        "QTableView { alternate-background-color: #FFFFFF;border:none;}")  ## 设置交替行的背景颜色为白色
                    port_info_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置表格控件不可编辑
                    port_info_table.setColumnCount(4)  # 4列
                    # 设置表头
                    port_info_table.setHorizontalHeaderLabels(["协议", "端口", "产品", "最后更新时间"])
                    # pro_port_table.horizontalHeader().setVisible(False)
                    # 设置第三列的可扩展
                    port_info_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
                    # 设置表头字体为微软雅黑，12号
                    header_font = QFont("Microsoft YaHei", 12)
                    port_info_table.horizontalHeader().setFont(header_font)

                    port_info_table.verticalHeader().setVisible(False)  # 隐藏垂直标头，即行号
                    # 设置表格的水平表头对齐方式为左对齐
                    port_info_table.horizontalHeader().setDefaultAlignment(QtCore.Qt.AlignLeft)


                    more_button = QPushButton("查看更多")
                    more_button.setCursor(Qt.PointingHandCursor)
                    more_button.setFixedWidth(120)
                    more_button.setStyleSheet(
                        "background-color:#99badd; color: #ffffff; border-radius:5px;height: 40px;border: 1px solid #3d8fde; font-family: Microsoft YaHei; font-size: 18px")

                    more_button.clicked.connect(
                        lambda _, more_button=more_button, pro_port_table=port_info_table, scroll_area=scroll_area,
                               ports_pros_updatTimes_products=ports_pros_updatTimes_products:
                        self.toggleMoreButton(more_button, pro_port_table, scroll_area, ports_pros_updatTimes_products))

                    # print(ports_pros_updatTimes_products)    
                    self.show_pro_port_table(port_info_table, scroll_area, ports_pros_updatTimes_products)

                if key == "vulns":
                    vuln_list = []
                    if data.get('vulns'):
                        for key, val in data["vulns"].items():
                            if data["vulns"][key]["verified"] is True:
                                vuln_list.append(key)
                    if vuln_list:
                        # 添加标题
                        title_label = QLabel("CVE_Verified:")  # 创建标题标签
                        title_label.setStyleSheet("font-size: 16px; font-weight: bold;")  # 设置标题样式

                        # 产品布局: 创建一个滚动区域
                        cve_scroll_area = QScrollArea()
                        # cve_scroll_area.setMaximumHeight(200)
                        cve_scroll_area.setWidgetResizable(True)  # 设置滚动区域大小自适应
                        cve_scroll_area.setStyleSheet(scroll_style)

                        cve_widget = QWidget()  # 创建一个小部件来包含所有产品按钮
                        cve_widget.setStyleSheet("border: none;")  # 设置 product_widget 的样式表，移除边框
                        vuln_layout = QGridLayout(cve_widget)

                        # 填充表格数据
                        num_columns = 3  # 每行最多显示的按钮数量
                        _row = 0
                        _col = 0
                        for vuln in vuln_list:
                            cve_button = QPushButton("", self)  # 去除首尾空格
                            cve_data = data["vulns"][vuln]
                            cve_button.clicked.connect(
                                lambda _, cve_data=cve_data: self.load_cve_detail_page(cve_data, vuln))
                            cve_button.setCursor(Qt.PointingHandCursor)
                            button_width = 210
                            button_height = 30
                            cve_button.setFixedSize(button_width, button_height)
                            cve_button.setStyleSheet(
                                "background-color: #99badd; color: white;text-align: center;border-radius:10px;")
                            cve_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)  # 设置按钮的大小策略为水平方向自适应，垂直方向固定

                            # 计算按钮文本的最大宽度
                            font_metrics = QFontMetrics(cve_button.font())
                            max_button_text_width = button_width - 20  # 例如，假设我们保留了10像素的填充空间

                            # 如果文本的宽度超过了按钮文本的最大宽度，则进行截断
                            if font_metrics.width(vuln.strip()) > max_button_text_width:
                                ellipsis_text = font_metrics.elidedText(vuln.strip(), Qt.ElideRight, max_button_text_width)
                            else:
                                ellipsis_text = vuln.strip()
                            cve_button.setText(ellipsis_text)
                            vuln_layout.addWidget(cve_button, _row, _col)
                            _col += 1
                            if _col == num_columns:
                                _col = 0
                                _row += 1

                # 创建表格
                tableWidget = QTableWidget()
                tableWidget.setColumnCount(2)  # 列数
                tableWidget.setShowGrid(False)  # 不显示网格线
                # 设置列宽
                tableWidget.setColumnWidth(0, 105)  # 第一列宽度
                tableWidget.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
                tableWidget.setEditTriggers(QTableWidget.NoEditTriggers)
                # tableWidget.setMinimumHeight(220)  # 设置表格的最小高度为200像素

                # 隐藏行号和列号
                tableWidget.verticalHeader().setVisible(False)
                tableWidget.horizontalHeader().setVisible(False)

                row_count = 0
                # 填充数据
                for key in ["city", "code", "domain", "server", "title", "org", "isp", "os", ]:
                    if key != "server" and key != 'title':
                        if not data[key]:
                            continue
                    # 获取值
                    value_text = ''
                    server_list = []
                    title_all = []
                    if key == "server":
                        port_list = list(data["ports"].keys())
                        for port in port_list:
                            port_data = data["ports"][port]
                            if port_data.get(key):
                                server_data = port_data.get("server")
                                if server_data:
                                    server_list.append(server_data)
                                else:
                                    continue
                        if len(server_list) > 0:
                            server_list = list(set(server_list))
                            value_text = str(server_list)
                        else:
                            continue
                    else:
                        if key == 'title':
                            for p in data['ports']:
                                if data['ports'][p].get('title'):
                                    title_all.append(data['ports'][p].get('title'))
                            if title_all:
                                title_all = str(title_all)
                                value_text = title_all
                            else:
                                continue
                        else:
                            value_text = f"{data[key]}"

                    # 创建表格项
                    key_item = QTableWidgetItem(key + " : ")

                    value_item = QTableWidgetItem(value_text)
                    color = QColor()
                    color.setNamedColor("#2368a1")
                    value_item.setForeground(color)
                    if key != "server" and key != 'title':
                        value_item.setToolTip(str(data[key]))
                    else:
                        if key == 'server':
                            value_item.setToolTip(str(server_list))
                        elif key == 'title':
                            value_item.setToolTip(str(title_all))

                    # 插入表格项到表格
                    tableWidget.insertRow(row_count)
                    tableWidget.setItem(row_count, 0, key_item)
                    tableWidget.setItem(row_count, 1, value_item)
                    # 增加行数
                    row_count += 1

                # 计算表格的总高度
                total_height = 0
                for row in range(tableWidget.rowCount()):
                    total_height += tableWidget.rowHeight(row)
                extra_space = 20
                # 设置表格的大小
                tableWidget.setMinimumHeight(total_height + extra_space)

            # 添加伸缩空间，确保按钮在窗口缩小时换行显示
            spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
            city_code_layout.addItem(spacer)
            info_layout.addLayout(city_code_layout)
            info_layout.addWidget(tableWidget)

            # CVE
            # 将小部件设置为滚动区域的内容
            if vuln_list:
                cve_scroll_area.setWidget(cve_widget)
                info_layout.addWidget(title_label)
                info_layout.addWidget(cve_scroll_area)
                info_layout.addStretch()

            # 将表格放入滚动区域
            scroll_area.setWidget(port_info_table)
            self.port_info_layout.addWidget(scroll_area)
            # 如果行数超过指定数，则显示“查看更多”按钮
            if len(ports_pros_updatTimes_products) > self.max_len:
                self.port_info_layout.addWidget(more_button)

            pro_port_layout.addLayout(self.port_info_layout)
            block_layout.addLayout(all_info_layout)
            self.data_layout.addWidget(block_frame)

    # ##############cve按钮查看详情
    def load_cve_detail_page(self, cve_data, vuln):
        self.show_detail_page(cve_data, vuln)

    def show_detail_page(self, cve_detail_info, vuln):
        detail_page = CveDetailPage(cve_detail_info, vuln)
        detail_page.exec_()

    def toggleMoreButton(self, more_button, pro_port_table, scroll_area, ports_pros_updatTimes_products):
        if more_button.text() == "查看更多":
            more_button.setText("取消查看")
            self.showAllRows(pro_port_table, ports_pros_updatTimes_products)
            scroll_area.setMinimumHeight(600)
        else:
            more_button.setText("查看更多")
            self.show_pro_port_table(pro_port_table, scroll_area, ports_pros_updatTimes_products)
            scroll_area.setMinimumHeight(350)

    def set_table_data(self, pro_port_table, ports_pros_updatTimes_products, model="default"):
        if model == "default":
            _data = list(ports_pros_updatTimes_products)[:self.max_len]
        else:
            _data = ports_pros_updatTimes_products[self.max_len:]

        # 将数据填充到表格中
        for row, item in enumerate(_data):  # 最多显示前20行
            item = ast.literal_eval(item)
            port = item["port"]
            protocol = item["pro"]
            update_time = item["update_time"]
            product = item["product"]

            port_button = QPushButton(port)
            port_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标悬停时的指针形状为手型
            port_button.setObjectName(port.strip())
            port_button.clicked.connect(lambda: self.display_info_clicked("port"))
            port_widget = QWidget()
            port_layout = QGridLayout(port_widget)
            port_layout.addWidget(port_button)

            protocol_button = QPushButton(protocol)
            protocol_button.setCursor(Qt.PointingHandCursor)  # 设置鼠标悬停时的指针形状为手型
            protocol_button.setObjectName(protocol.strip())
            protocol_button.clicked.connect(lambda: self.display_info_clicked("pro"))

            protocol_button.setToolTip(protocol)

            protocol_widget = QWidget()
            protocol_layout = QGridLayout(protocol_widget)
            protocol_layout.addWidget(protocol_button)

            update_time_item = QTableWidgetItem(update_time)

            products = product.split(",")
            # 创建一个 QWidget 用于放置按钮
            product_widget = QWidget()
            # 创建按钮布局
            product_layout = QGridLayout(product_widget)
            # 填充表格数据
            num_columns = 3  # 每行最多显示的按钮数量
            _row = 0
            _col = 0
            for product in products:
                if len(str(product).strip()) > 0:
                    # button = QPushButton(p.strip())  # 去除首尾空格
                    product_button = QPushButton("", self)  # 去除首尾空格
                    product_button.setCursor(Qt.PointingHandCursor)
                    product_button.setStyleSheet(
                        "background-color: #77b2df; color: white;text-align: center;border-radius:10px;")

                    product_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)  # 设置按钮的大小策略为水平方向自适应，垂直方向固定
                    product_button.setMinimumWidth(self.product_bt_min_width)


                    # 计算按钮文本的最大宽度
                    font_metrics = QFontMetrics(product_button.font())
                    max_button_text_width = self.product_bt_min_width - 20  # 保留了20像素的填充空间

                    # 如果文本的宽度超过了按钮文本的最大宽度，则进行截断
                    if font_metrics.width(product.strip()) > max_button_text_width:
                        ellipsis_text = font_metrics.elidedText(product.strip(), Qt.ElideRight, max_button_text_width)
                        product_button.setToolTip(product.strip())  # 只有当需要时才设置提示
                    else:
                        ellipsis_text = product.strip()

                    product_button.setText(ellipsis_text)
                    product_button.setObjectName(product.strip())
                    product_button.clicked.connect(lambda: self.display_info_clicked("product"))
                    product_button.setToolTip(product.strip())
                    product_layout.addWidget(product_button, _row, _col)
                    _col += 1
                    if _col == num_columns:
                        _col = 0
                        ellipsis_button = QPushButton("...")
                        ellipsis_button.setFixedSize(30, 30)
                        product_layout.addWidget(ellipsis_button, 0, num_columns)

            # 设置按钮的样式表
            button_style = "background-color:#678acd; color: white;text-align: center;border-radius:10px;margin-left:5px; font-size:20px"
            protocol_button.setStyleSheet(button_style)

            port_button.setStyleSheet(
                "background-color:#99badd; color: white;text-align: center;border-radius:10px;margin-left:5px;")
            port_button.setMinimumWidth(80)  # 设置按钮的最小宽度
            protocol_button.setMinimumWidth(110)  # 设置按钮的最小宽度
            if model == "default":
                pro_port_table.setCellWidget(row, 0, protocol_widget)  # 第一列：协议
                pro_port_table.setCellWidget(row, 1, port_widget)  # 第二列：端口
                pro_port_table.setCellWidget(row, 2, product_widget)
                pro_port_table.setItem(row, 3, update_time_item)  # 第三列：更新时间

                pro_port_table.resizeColumnsToContents()
                pro_port_table.resizeRowsToContents()
                pro_port_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
            else:
                pro_port_table.setRowCount(pro_port_table.rowCount() + 1)
                pro_port_table.setCellWidget(row + self.max_len, 0, protocol_widget)  # 第一列：协议
                pro_port_table.setCellWidget(row + self.max_len, 1, port_widget)  # 第二列：端口
                pro_port_table.setCellWidget(row + self.max_len, 2, product_widget)
                pro_port_table.setItem(row + self.max_len, 3, update_time_item)  # 第三列：更新时间
                pro_port_table.setRowHeight(row + self.max_len, 60)
                pro_port_table.update()  # 强制更新布局，如果不添加的话，会照成表格不会自适应

            # 在网格布局中添加一个空白的 QWidget 作为弹簧，让产品按钮靠左显示。
            spring_widget = QWidget()
            product_layout.addWidget(spring_widget, 0, num_columns + 1)
            # 设置空白 QWidget 的弹性空间
            product_layout.setColumnStretch(num_columns + 1, 1)

    def show_pro_port_table(self, pro_port_table, scroll_area, data_list_table):
        # 设置表格的行数和列数
        if len(data_list_table) > self.max_len:
            pro_port_table.setRowCount(self.max_len)
        else:
            pro_port_table.setRowCount(len(data_list_table))
            scroll_area.setMinimumHeight(120)

        self.set_table_data(pro_port_table, data_list_table, model="default")

    def showAllRows(self, pro_port_table, ports_pros_updatTimes_products):
        self.set_table_data(pro_port_table, ports_pros_updatTimes_products, model="showAllRows")
        # # 调整表格的大小以适应按钮

    def prev_page(self):
        if self.page_index > 0:
            self.page_index -= 1
            self.current_page -= 1
            self.update_display()

    def next_page(self):
        if (self.page_index + 1) * self.items_per_page < self.total:
            self.page_index += 1
            self.current_page += 1
            self.update_display()

    def go_to_page(self):
        page_num = int(self.page_input.text()) - 1
        if 0 <= page_num < self.total // self.items_per_page + 1:
            self.page_index = page_num
            self.current_page = page_num + 1
            self.update_display()

    def change_items_per_page(self, index):
        self.items_per_page = int(self.items_per_page_combo.currentText())
        self.page_index = 0
        self.current_page = 1
        self.update_display()

    def update_display(self):
        self.clear_layout(self.data_layout)
        self.right_display_data()
        self.update_pagination_info()
        self.mainPage_scroll_area.verticalScrollBar().setValue(0)

    def clear_layout(self, layout):
        while layout.count():
            child = layout.takeAt(0)
            if child.widget():
                child.widget().deleteLater()

    def get_totle_pages(self):
        if self.search_data_Table:
            self.total = len(self.search_data_Table.keys())
            total_pages = self.total // self.items_per_page
            if self.total % self.items_per_page != 0:
                total_pages += 1  # 如果有余数，向上取整
        else:
            self.total = len(self.Summary_Table.keys())
            total_pages = self.total // self.items_per_page
            if self.total % self.items_per_page != 0:
                total_pages += 1  # 如果有余数，向上取整

        return total_pages, self.total

    def update_pagination_info(self):
        total_pages, total = self.get_totle_pages()
        self.count_label.setText(f"共{total}条数据，共{total_pages}页,当前{self.current_page}页")

    def show_detail(self, data):
        try:
            detail_window = DetailPage(data)
            self.detail_windows.append(detail_window)
            detail_window.show()
        except Exception as e:
            traceback.print_exc()
            QMessageBox.critical(self, "错误", str(e))

    def create_tmp_table(self, ):
        self.tmp_port_table = {}
        self.tmp_protocol_table = {}
        self.tmp_vuln_table = {}
        self.tmp_cve_verify_table = {}
        self.tmp_product_table = {}
        self.tmp_city_table = {}
        self.tmp_ipc_table = {}

        for ip_address, ip_data_dict in self.search_data_Table.items():
            # 更新端口表
            port_info_dict = ip_data_dict.get("ports", {})
            if port_info_dict:
                for port, _ in port_info_dict.items():
                    self.tmp_port_table.setdefault(port, []).append(
                        ip_address)  # setdefault()方法可以实现如果字典中不存在某个键，则设置该键的默认值，然后返回该键对应的值。如果该键已经存在，则直接返回该键对应的值。避免手动检查键是否存在，简化代码
                    # 更新协议表
                    port_info = port_info_dict.get(port, {})
                    if port_info:
                        pro = port_info.get("pro")
                        if pro:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.tmp_protocol_table.setdefault(pro, []):
                                self.tmp_protocol_table[pro].append(ip_address)
                    # 更新product表
                    product = port_info.get("product")
                    if product:
                        product_list = str(product).split(",")
                        for product in product_list:
                            # 检查 ip_address 是否已经存在于列表中
                            if ip_address not in self.tmp_product_table.setdefault(product, []):
                                self.tmp_product_table[product].append(ip_address)

                                # 更新vuln表
            vulns_info_dict = ip_data_dict.get("vulns", {})
            if vulns_info_dict:
                for vuln, _ in vulns_info_dict.items():
                    self.tmp_vuln_table.setdefault(vuln, []).append(ip_address)
                    # 更新验证cve的表
                    if _.get("verified") is True:
                        self.tmp_cve_verify_table.setdefault(vuln, []).append(ip_address)
                        # 更新city表
            city = ip_data_dict.get("city")
            if city:
                self.tmp_city_table.setdefault(city, []).append(ip_address)
            # 更新IPC表
            ip = ip_data_dict.get("ip")
            if ip:
                ipc = ".".join(ip.split(".")[:3]) + ".0/24"  # 取 IP 的 C 段 
                if ipc:
                    self.tmp_ipc_table.setdefault(ipc, []).append(
                        ip)  # setdefault()方法可以实现如果字典中不存在某个键，则设置该键的默认值，然后返回该键对应的值。如果该键已经存在，则直接返回该键对应的值。避免手动检查键是否存在，简化代码

    def search_data(self, init=False):
        if init:
            self.page_index = 0
            self.search_data_Table = {}
            self.update_display()
            self.init_left_page(self.data_list)

        filter_text = self.search_input.text().strip()
        if filter_text:
            condition_structure = self.parse_condition(filter_text)
            # 获取满足条件的数据列表
            self.search_data_Table = self.get_filtered_data(condition_structure)
            # 创建临时的统计字段表
            self.create_tmp_table()
            self.page_index = 0
            self.current_page = 1
            self.update_display()
            self.init_left_page(search_data=True)
        else:
            self.current_page = 1
            self.search_data_Table = {}
            self.update_display()
            self.init_left_page(search_data=False)


def extract_title_from_http_response(http_response):
    # 定义匹配标题的正则表达式
    title_regex = r'<title>(.*?)</title>'
    # 使用 re.findall() 函数来查找所有匹配的标题
    try:
        title = re.findall(title_regex, http_response, re.IGNORECASE)[0]
    except:
        title = ''
    return title


# geoip_reader = geoip2.database.Reader(f'{os.path.dirname(os.path.abspath(__file__))}/db/GeoLite2-Country.mmdb')
now_time = datetime.now().strftime("%Y/%m/%d %H:%M")

if __name__ == '__main__':
    data_list = []
    ip_hash_table = {}
    with open('example.json', 'r', encoding='utf-8', errors='ignore') as f:
        ip_hash_table = json.load(f)
        for ip in ip_hash_table:
            data_list.append(ip_hash_table[ip])

    print(len(data_list))
    app = QApplication(sys.argv)
    search_page = DataDisplay(data_list)

    # 设置窗口为最大化模式，不覆盖任务栏
    search_page.setWindowState(search_page.windowState() | Qt.WindowMaximized)
    search_page.show()

    sys.exit(app.exec_())
