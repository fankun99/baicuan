import os
import shutil
from datetime import datetime
import json
import base64
import time
import traceback
from configparser import ConfigParser

import requests
import shodan
from shodan import APIError

requests.packages.urllib3.disable_warnings()

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QObject, QTimer, QMutex
from PyQt5.QtGui import QFont
from PyQt5.QtGui import QIcon
import csv
import sys
from PyQt5.QtWidgets import QApplication, QMainWindow, QLabel, QVBoxLayout, QWidget, QHBoxLayout, QComboBox, \
    QPushButton, QLineEdit, \
    QTextEdit, QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy, QFileDialog, QTabWidget, QSpacerItem, \
    QAbstractItemView, \
    QGroupBox, QCheckBox, QMessageBox, QScrollArea, QDialog, QProgressBar
from configobj import ConfigObj
import dataview as data_view

from qt_material import apply_stylesheet  # 导入qt_material

if sys.argv[-1].endswith("exe"):
    # 获取临时目录路径
    temp_dir = sys._MEIPASS
    # 获取icon释放的文件
    icon_path = os.path.join(temp_dir, 'icon')
    current_directory = os.getcwd()
    folder_path = os.path.join(current_directory, "icon")
    if not os.path.exists(folder_path):
        try:
            shutil.copytree(icon_path, folder_path)
        except Exception as e:
            print(f"An error occurred: {e}")



config_dic = {}
cf = ConfigParser()


# 读取config.ini文件，获取需要的配置信息
try:
    cf.read('config.ini')
    proxy_server_ip = cf.get('global', 'proxy_server_ip')
    proxy_port = cf.get('global', 'proxy_port')
    proxy_type = cf.get('global', 'proxy_type')

    config_dic['proxy_server_ip'] = proxy_server_ip
    config_dic['proxy_port'] = proxy_port
    config_dic['proxy_type'] = proxy_type
    if  proxy_type and proxy_server_ip and proxy_port and proxy_type:
        g_proxies = {
            'http': f'{proxy_type}://{proxy_server_ip}:{proxy_port}',
            'https': f'{proxy_type}://{proxy_server_ip}:{proxy_port}',
        }
    else:
        g_proxies = {}
    config_dic['proxies'] = g_proxies
except:
    g_proxies = {}

button_style = """
            background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #4682B4, stop:1 #5F9EA0);
            border: 2px solid #C0C0C0;
            border-radius: 15px; /* 圆角半径 */
            padding: 5px 10px; /* 按钮内边距 */
            color: white;
            border-radius: 13px;
"""

# 重写shodan api的请求方法，以便设置http请求中的超时、忽略证书、代理
def _new_request(self, function, params, service='shodan', method='get', json_data=None):
    # Add the API key parameter automatically
    params['key'] = self.api_key

    # Determine the base_url based on which service we're interacting with
    base_url = {
        'shodan': self.base_url,
        'exploits': self.base_exploits_url,
        'trends': self.base_trends_url,
    }.get(service, 'shodan')

    # Wait for API rate limit
    if self._api_query_time is not None and self.api_rate_limit > 0:
        while (1.0 / self.api_rate_limit) + self._api_query_time >= time.time():
            time.sleep(0.1 / self.api_rate_limit)

    # Set timeout in seconds
    timeout = 120  # Adjust as needed

    # Send the request with timeout
    try:
        method = method.lower()
        with requests.Session() as session:
            session.timeout = timeout
            session.proxies = g_proxies
            if method == 'post':
                if json_data:
                    data = session.post(base_url + function, params=params,
                                        data=json.dumps(json_data),
                                        headers={'content-type': 'application/json'},
                                        timeout=timeout, verify=False,
                                        )
                else:
                    data = session.post(base_url + function, params, timeout=timeout, verify=False, )
            elif method == 'put':
                data = session.put(base_url + function, params=params, verify=False, )
            elif method == 'delete':
                data = session.delete(base_url + function, params=params, verify=False, )
            else:
                data = session.get(base_url + function, params=params, verify=False, )
        self._api_query_time = time.time()
    except Exception:
        raise APIError('Unable to connect to Shodan')

    # Check that the API key wasn't rejected
    if data.status_code == 401:
        try:
            # Return the actual error message if the API returned valid JSON
            error = data.json()['error']
        except Exception as e:
            # If the response looks like HTML then it's probably the 401 page that nginx returns
            # for 401 responses by default
            if data.text.startswith('<'):
                error = 'Invalid API key'
            else:
                # Otherwise lets raise the error message
                error = u'{}'.format(e)

        raise APIError(error)
    elif data.status_code == 403:
        raise APIError('Access denied (403 Forbidden)')
    elif data.status_code == 502:
        raise APIError('Bad Gateway (502)')

    # Parse the text into JSON
    try:
        data = data.json()
    except ValueError:
        print(data.text)
        raise APIError('Unable to parse JSON response')

    # Raise an exception if an error occurred
    if type(data) == dict and 'error' in data:
        raise APIError(data['error'])

    # Return the data
    return data


# 保存原始的 _request 方法
shodan_old_request = shodan.Shodan._request

# 将新定义的 _request 方法赋值给 Shodan 类的 _request 属性
shodan.Shodan._old_request = shodan_old_request
shodan.Shodan._request = _new_request



class Qprogressbar(QDialog):
    '''进度条类'''
    def __init__(self):
        super().__init__()
        self.progress_bar = QProgressBar()
        self.initUI()

    def initUI(self):
        self.setWindowFlag(Qt.WindowCloseButtonHint, False)  # 禁用关闭按钮
        self.setWindowFlag(Qt.WindowContextHelpButtonHint, False)  # 去除问号按钮
        self.setModal(True)  # 设置为模态对话框
        # 创建进度条
        self.progress_bar.setRange(0, 0)  # 设置范围为0到0，使进度条无限循环
        # 使用样式表增加进度条的高度
        self.progress_bar.setStyleSheet(
            "QProgressBar { border: 1px solid grey; border-radius: 5px; height: 50px;width :610px; }")

        # 创建布局并添加进度条和按钮
        layout = QVBoxLayout()
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)
        self.setWindowTitle('正在查询...')



class EasySearchPage(QWidget):
    '''快捷搜索页面'''
    def __init__(self):
        super().__init__()
        self.combo_box_style = """
                QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
                    background-color: white;
                    height: 45px;
                }
                QComboBox::down-arrow {
                    image: url(icon/down.png);  /* 替换为您想要的箭头图标路径 */
                    height: 35px;
                }
                QComboBox::drop-down {
                    border: none;  /* 设置下拉按钮无边框 */
                }
            """
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()  # 创建垂直布局
        layout.setContentsMargins(0, 0, 0, 0)  # 去除布局边距
        self.setStyleSheet("background-color: #fff;")  # 设置背景颜色为白色

        # 添加顶部垂直间隔
        topSpacer = QSpacerItem(20, 30, QSizePolicy.Minimum,
                                QSizePolicy.Minimum)  # 创建了一个垂直的空白空间，宽度为 20 个像素，高度为 30 个像素，并且它会尽可能地小以适应布局
        layout.addItem(topSpacer)

        saveButtonLayout = QHBoxLayout()  # 创建水平布局
        spacerItem = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        saveButtonLayout.addItem(spacerItem)

        self.from_comboBox = QComboBox()  # 创建下拉框
        self.from_comboBox.addItems(
            ["fofa", "shodan"])  # 添加下拉选项
        self.from_comboBox.setStyleSheet(self.combo_box_style)
        saveButtonLayout.addWidget(self.from_comboBox)  # 添加搜索按钮到布局

        self.search_button = QPushButton("搜索", self)  # 创建搜索按钮
        self.search_button.clicked.connect(self.slot_search)  # 连接点击事件到saveValues函数
        self.search_button.setStyleSheet(
            "QPushButton { background-color: #007BFF; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 18px; }")
        saveButtonLayout.addWidget(self.search_button)  # 添加搜索按钮到布局
        layout.addLayout(saveButtonLayout)  # 将按钮布局添加到主布局

        self.scroll_area = QScrollArea()  # 创建滚动区域
        self.scroll_area.setStyleSheet("border: none;")  # 设置滚动区域的边框不可见
        self.scroll_area.setWidgetResizable(True)  # 设置滚动区域的widget可以调整大小
        self.groupWidget = QWidget()
        self.groupWidget.setStyleSheet("background-color: #fff;")   
        self.groupLayout = QVBoxLayout(self.groupWidget)  # 创建widget的垂直布局
        self.groupLayout.setAlignment(Qt.AlignTop)  # 设置布局顶部对齐
        self.create_easy_search_widget(is_initial=True)  # 添加初始小部件
        self.scroll_area.setWidget(self.groupWidget)  # 将widget添加到滚动区域
        layout.addWidget(self.scroll_area)  # 将滚动区域添加到主布局
        self.setLayout(layout)  # 设置主布局

    def create_easy_search_widget(self, is_initial=False):
        widgetLayout = QHBoxLayout()  # 创建水平布局

        self.search_field_comboBox = QComboBox()  # 创建下拉框
        self.search_field_comboBox.addItems(
            ["ip/段", "域名", "证书", "端口", "国家", "title", "header", "body", "组织", "自定义"])  # 添加下拉选项
        self.search_field_comboBox.setStyleSheet(self.combo_box_style)
        self.search_field_comboBox.setObjectName('search_type')

        if not is_initial:
            self.condition_comboBox = QComboBox(self)  # 创建下拉框
            self.condition_comboBox.addItems(["或", ])  # 添加下拉选项
            self.condition_comboBox.setStyleSheet(self.combo_box_style)
            self.condition_comboBox.setObjectName('relationship')
            widgetLayout.addWidget(self.condition_comboBox)  # 将下拉框添加到水平布局
            spacerItem = QSpacerItem(5, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)
            widgetLayout.addItem(spacerItem)  # 在输入框和下拉选项中添加固定大小的水平间隔

        widgetLayout.addWidget(self.search_field_comboBox)  # 将下拉框添加到水平布局
        self.input = QLineEdit()  # 创建文本输入框
        self.input.setObjectName('condition')
        self.input.setStyleSheet(
            "QLineEdit { background-color: #fff; color: #333; border: 2px solid #ccc; border-radius: 15px; padding: 10px; font-size: 18px; }")
        widgetLayout.addWidget(self.input)  # 将文本输入框添加到水平布局

        if not is_initial:
            self.remove_button = QPushButton("-", self)  # 创建删除按钮
            self.remove_button.clicked.connect(
                lambda: self.removeWidgetLayout(widgetLayout))  # 连接点击事件到removeWidgetLayout函数
            self.remove_button.setStyleSheet(
                "QPushButton { background-color: #DC3545; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 24px; }")
            widgetLayout.addWidget(self.remove_button)  # 将删除按钮添加到水平布局
            # 在“-”按钮后插入“+”按钮
            widgetLayout.insertWidget(widgetLayout.indexOf(self.remove_button) + 1, self.add_button)

        if is_initial:
            self.add_button = QPushButton("+", self)  # 创建添加按钮
            self.add_button.clicked.connect(lambda: self.create_easy_search_widget())  # 连接点击事件到addWidgets函数
            self.add_button.setStyleSheet(
                "QPushButton { background-color: #28A745; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 24px; }")
            widgetLayout.addWidget(self.add_button)  # 将添加按钮添加到水平布局

        self.groupLayout.addLayout(widgetLayout)  # 将水平布局添加到垂直布局

    def removeWidgetLayout(self, layout):
        index = self.groupLayout.indexOf(layout)  # 获取布局在垂直布局中的索引
        last_index = self.groupLayout.count() - 1  # 获取垂直布局中最后一个小部件的索引
        if index == last_index:
            last_layout = self.groupLayout.itemAt(index - 1).layout()  # 获取上一个布局
            last_layout.addWidget(self.add_button)  # 在上一个布局中添加添加按钮

        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()  # 获取小部件
            if widget is not None:
                widget.deleteLater()  # 删除小部件
        layout.deleteLater()  # 删除布局

    def parse_fofa_query(self, search_combo_box, line_edit):
        fofa_ip_search = ' ip="{}" '
        fofa_domain_search = ' domain="{}" '
        fofa_cname_search = ' cname="{}" '
        fofa_host_search = ' host=".{}" '
        fofa_cert_search = ' cert="{}" '
        fofa_port_search = ' port="{}" '
        fofa_country_search = ' country="{}" '
        fofa_title_search = ' title="{}" '
        fofa_body_search = ' body="{}" '
        fofa_header_search = ' header="{}" '
        fofa_org_search = ' org="{}" '
        query_str = ''

        if not search_combo_box:
            return ''
        query_type = search_combo_box.currentText().strip()
        if query_type == "":
            return ''
        if not line_edit:
            return ''
        content = line_edit.text().strip()
        if content == '':
            return ''

        if query_type == 'ip/段':
            query_str += fofa_ip_search.format(content)
        elif query_type == '域名':
            query_str += fofa_domain_search.format(content) + '||'
            query_str += fofa_cname_search.format(content) + '||'
            query_str += fofa_host_search.format(content) + '||'
            query_str += fofa_cert_search.format(content)
        elif query_type == '证书':
            query_str += fofa_cert_search.format(content)
        elif query_type == '端口':
            query_str += fofa_port_search.format(content)
        elif query_type == '国家':
            query_str += fofa_country_search.format(content)
        elif query_type == 'title':
            query_str += fofa_title_search.format(content)
        elif query_type == 'header':
            query_str += fofa_header_search.format(content)
        elif query_type == 'body':
            query_str += fofa_body_search.format(content)
        elif query_type == '组织':
            query_str += fofa_org_search.format(content)
        elif query_type == '自定义':
            try:
                content = content.split('fofa:')[1]
                query_str = content
            except:
                print('format error. it must like  fofa:header="123" || body="456" ')
        return query_str

    def parse_shodan_query(self, search_combo_box, line_edit):
        shodan_ip_search = 'ip:"{}"'
        shodan_net_search = 'net:"{}"'
        shodan_domain_search = '{}'
        shodan_host1_search = ' hostname="{}"'
        shodan_host2_search = ' hostname="*.{}"'
        shodan_cert_search = 'ssl:"{}"'
        shodan_port_search = 'port:"{}"'
        shodan_country_search = 'country:"{}"'
        shodan_title_search = 'http.title:"{}"'
        shodan_body_search = 'http.html="{}"'
        shodan_header_search = 'http.component:"Server" http.component.data:"{}"'
        shodan_org_search = 'org:"{}"'
        query_str = ''

        if not search_combo_box:
            return ''
        query_type = search_combo_box.currentText().strip()
        if query_type == "":
            return ''
        if not line_edit:
            return ''
        content = line_edit.text().strip()
        if content == '':
            return ''

        if query_type == 'ip/段':
            if '/' not in content:
                query_str += shodan_ip_search.format(content)
            else:
                query_str += shodan_net_search.format(content)
        elif query_type == '域名':
            query_str += shodan_domain_search.format(content) + '||'
            query_str += shodan_host1_search.format(content) + '||'
            query_str += shodan_host2_search.format(content)
        elif query_type == '证书':
            query_str += shodan_cert_search.format(content)
        elif query_type == '端口':
            query_str += shodan_port_search.format(content)
        elif query_type == '国家':
            query_str += shodan_country_search.format(content)
        elif query_type == 'title':
            query_str += shodan_title_search.format(content)
        elif query_type == 'header':
            query_str += shodan_header_search.format(content)
        elif query_type == 'body':
            query_str += shodan_body_search.format(content)
        elif query_type == '组织':
            query_str += shodan_org_search.format(content)
        elif query_type == '自定义':
            try:
                content = content.split('shodan:')[1]
                query_str = content
            except:
                print('format error. it must like  fofa:header="123" || body="456" ')
        return query_str.strip()

    def slot_search(self):
        '''点击搜索按钮触发'''
        fofa_statement_text = ''
        shodan_statement_text = ''
        condition_count = self.groupLayout.count()
        datacenter = self.from_comboBox.currentText()
        print('datacenter choose:', datacenter)
        for index in range(condition_count):
            try:
                sub_groupLayout = self.groupLayout.itemAt(index).layout()  # 获取垂直布局中的水平布局

                search_combo_box = None
                relation_combo_box = None
                line_edit = None

                for i in range(sub_groupLayout.count()):  # 遍历水平布局中的小部件
                    item = sub_groupLayout.itemAt(i)
                    try:
                        obj = item.widget()
                    except:
                        continue
                    if obj:
                        if obj.objectName() == 'search_type':  # 搜索类型（字段）下拉菜单
                            search_combo_box = obj
                        elif obj.objectName() == 'condition':  # 搜素条件（即语句）文本框
                            line_edit = obj
                        elif obj.objectName() == 'relationship':  # 逻辑关系下拉菜单
                            relation_combo_box = obj

                if search_combo_box and relation_combo_box and line_edit:
                    print(
                        f"第{index + 1}行 搜索字段: {search_combo_box.currentText()}, 逻辑关系: {relation_combo_box.currentText()}, 文本: {line_edit.text()}")

                elif search_combo_box and line_edit:
                    print(f"第{index + 1}行 搜索字段: {search_combo_box.currentText()}, 文本: {line_edit.text()}")
                else:
                    print("找不到组件")

                if index == condition_count - 1:  # end line do not need append '||'
                    if datacenter == 'fofa':
                        new_condition = self.parse_fofa_query(search_combo_box, line_edit)
                        if new_condition:
                            fofa_statement_text += new_condition
                    elif datacenter == 'shodan':
                        new_condition = self.parse_shodan_query(search_combo_box, line_edit)
                        if new_condition:
                            shodan_statement_text += new_condition
                else:
                    if datacenter == 'fofa':
                        new_condition = self.parse_fofa_query(search_combo_box, line_edit)
                        if new_condition:
                            fofa_statement_text += new_condition
                            fofa_statement_text += '||'
                    elif datacenter == 'shodan':
                        new_condition = self.parse_shodan_query(search_combo_box, line_edit)
                        if new_condition:
                            shodan_statement_text += new_condition
                            shodan_statement_text += '||'
            except Exception as e:
                print(e)
                pass

        if datacenter == 'fofa':
            print(fofa_statement_text)
            if fofa_statement_text.strip() == '':
                print('[-] error, check your input')
                QMessageBox.information(self, "错误",
                                        "error, 请检查你的输入")
                return
        elif datacenter == 'shodan':
            print(shodan_statement_text)
            if shodan_statement_text.strip() == '':
                print('[-] error, check your input')
                QMessageBox.information(self, "错误",
                                        "error, 请检查你的输入")
                return
        # 创建进度条
        self.progress = Qprogressbar()
        self.progress.setModal(True)
        self.progress.show()

        if datacenter == 'fofa':
            qbase64 = base64.b64encode(fofa_statement_text.encode('utf-8')).decode('ascii')
            num = window.fofa_page.num_select_combo.currentText()
            query_url = 'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&page={}&size={}&fields=host,ip,port,title,domain,country,protocol,server,product,lastupdatetime,country_name'.format(
                config_dic['fofa']['fofa_mail'], config_dic['fofa']['fofa_key'],
                qbase64, '1', num)
            if window.fofa_page.search_thread:
                print('[-] error, fofa查询线程正在运行，请等待结束后再使用快捷查询')
                QMessageBox.information(self, "错误",
                                        "error, fofa查询线程正在运行，请等待结束后再使用快捷查询")
                return
            self.worker_thread = FofaSearchThread(url=query_url)
            self.worker_thread.finished.connect(self.progress.close)
            self.worker_thread.finished.connect(lambda html: window.fofa_page.slot_draw_table(html))
            self.worker_thread.finished.connect(window.slot_switch_to_fofa)
            self.worker_thread.start()

        elif datacenter == 'shodan':
            querys = ''
            if '||' in shodan_statement_text:
                try:
                    querys = shodan_statement_text.strip().split('||')
                except:
                    print('[-] error, 请检查你的输入')
                    QMessageBox.information(self, "错误",
                                            "error， 请检查你的输入")
                    return
            else:
                querys = shodan_statement_text
            self.shodan_api_key = config_dic['shodan']['shodan_api']
            search_host = querys
            page = 1
            self.api = shodan.Shodan(self.shodan_api_key, proxies=g_proxies)
            self.shodan_search_type = 'Host'
            try:
                self.shodan_search_limit_per_page = int(
                    window.shodan_page.api_limit_input.text()) if window.shodan_page.api_limit_input.text() else 1000
            except:
                traceback.print_exc()
            _note = search_host if isinstance(search_host, str) else ",".join(search_host)
            window.shodan_page.log_display.append(f'正在查询:  {_note} ...' + '\n')
            QApplication.processEvents()  # 刷新页面，显示正在查询

            args = {
                'api': self.api,
                'shodan_search_limit_per_page': self.shodan_search_limit_per_page,
                'page': page,
                'shodan_search_type': self.shodan_search_type,
                'search_host': search_host,
            }

            if window.shodan_page.search_thread:
                print('searching now.. not over')
                print('[-] error, shodan查询线程正在运行，请等待其结束再查询')
                QMessageBox.information(self, "错误",
                                        "error, shodan查询线程正在运行，请等待其结束再查询")
                return
            else:
                print('search thread start..')
                self.worker_thread = ShodanSearchThread(args)
                self.worker_thread.finished.connect(lambda results: window.shodan_page.slot_draw_table(results))
                self.worker_thread.close_progress_bar.connect(self.progress.close)
                self.worker_thread.close_progress_bar.connect(window.slot_switch_to_shodan)
                self.worker_thread.start()


class AllInOnePage(QWidget):
    signal_task_done = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.combo_box_style = """
                QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
                    background-color: white;
                    height: 45px;
                }
                QComboBox::down-arrow {
                    image: url(icon/down.png);  /* 替换为您想要的箭头图标路径 */
                    height: 35px;
                }
                QComboBox::drop-down {
                    border: none;  /* 设置下拉按钮无边框 */
                }
            """
        self.progress = None
        self.last_search_thread = None
        self.total_data_list = []
        self.merge_data_list = []
        self.search_thread_list = []
        self.view_page = None
        self.view_page_list = []
        self.thread_num_remain = 0
        self.signal_task_done.connect(self.slot_check_task_done)

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()  # 创建垂直布局
        layout.setContentsMargins(0, 0, 0, 0)  # 去除布局边距
        self.setStyleSheet("background-color: #fff;")

        # 添加顶部垂直间隔
        topSpacer = QSpacerItem(20, 30, QSizePolicy.Minimum,
                                QSizePolicy.Minimum)  # 创建了一个垂直的空白空间，宽度为 20 个像素，高度为 30 个像素，并且它会尽可能地小以适应布局
        layout.addItem(topSpacer)

        saveButtonLayout = QHBoxLayout()  # 创建水平布局
        spacerItem = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        saveButtonLayout.addItem(spacerItem)

        # 启动UI按钮
        self.run_ui_button = QPushButton("启动UI", self)  # 直接启动数据融合查询UI的按钮
        self.run_ui_button.clicked.connect(lambda: self.slot_parse_data())  #
        self.run_ui_button.setStyleSheet(
            "QPushButton { background-color: #e21f6d; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 18px; }")
        saveButtonLayout.addWidget(self.run_ui_button)  # 添加启动UI按钮到布局

        # 搜索按钮
        self.search_button = QPushButton("搜索", self)  # 创建搜索按钮
        self.search_button.clicked.connect(self.slot_search)  # 连接点击事件到saveValues函数
        self.search_button.setStyleSheet(
            "QPushButton { background-color: #007BFF; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 18px; }")
        saveButtonLayout.addWidget(self.search_button)  # 添加搜索按钮到布局

        layout.addLayout(saveButtonLayout)  # 将按钮布局添加到主布局

        self.scroll_area = QScrollArea()  # 创建滚动区域
        self.scroll_area.setStyleSheet("border: none;")  # 设置滚动区域的边框为透明
        self.scroll_area.setWidgetResizable(True)  # 设置滚动区域的widget可以调整大小
        self.groupWidget = QWidget()  # 创建widget
        self.groupWidget.setStyleSheet("background-color: #fff;")  # 设置widget背景颜色
        self.groupLayout = QVBoxLayout(self.groupWidget)  # 创建widget的垂直布局
        self.groupLayout.setAlignment(Qt.AlignTop)  # 设置布局顶部对齐
        self.create_allinone_widget(is_initial=True)  # 添加初始小部件
        self.scroll_area.setWidget(self.groupWidget)  # 将widget添加到滚动区域
        layout.addWidget(self.scroll_area)  # 将滚动区域添加到主布局
        self.setLayout(layout)  # 设置主布局

    def create_allinone_widget(self, is_initial=False):
        widgetLayout = QHBoxLayout()  # 创建水平布局

        self.search_field_comboBox = QComboBox()  # 创建下拉框
        self.search_field_comboBox.addItems(
            ["ip/段", "域名", "证书", "端口", "国家", "title", "header", "body", "组织", "自定义"])  # 添加下拉选项
        self.search_field_comboBox.setStyleSheet(self.combo_box_style)
        self.search_field_comboBox.setObjectName('search_type')

        if not is_initial:
            self.condition_comboBox = QComboBox(self)  # 创建下拉框
            self.condition_comboBox.addItems(["或", ])  # 添加下拉选项
            self.condition_comboBox.setStyleSheet(self.combo_box_style)
            self.condition_comboBox.setObjectName('relationship')
            widgetLayout.addWidget(self.condition_comboBox)  # 将下拉框添加到水平布局
            spacerItem = QSpacerItem(5, 20, QSizePolicy.Fixed, QSizePolicy.Minimum)
            widgetLayout.addItem(spacerItem)  # 在输入框和下拉选项中添加固定大小的水平间隔

        widgetLayout.addWidget(self.search_field_comboBox)  # 将下拉框添加到水平布局
        self.input = QLineEdit()  # 创建文本输入框
        self.input.setObjectName('condition')
        self.input.setStyleSheet(
            "QLineEdit { background-color: #fff; color: #333; border: 2px solid #ccc; border-radius: 15px; padding: 10px; font-size: 18px; }")
        font = QFont("Microsoft YaHei", 18)  # 字体和大小
        self.input.setFont(font)
        widgetLayout.addWidget(self.input)  # 将文本输入框添加到水平布局

        if not is_initial:
            self.remove_button = QPushButton("-", self)  # 创建删除按钮
            self.remove_button.clicked.connect(
                lambda: self.removeWidgetLayout(widgetLayout))  # 连接点击事件到removeWidgetLayout函数
            self.remove_button.setStyleSheet(
                "QPushButton { background-color: #DC3545; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 24px; }")
            widgetLayout.addWidget(self.remove_button)  # 将删除按钮添加到水平布局
            # 在“-”按钮后插入“+”按钮
            widgetLayout.insertWidget(widgetLayout.indexOf(self.remove_button) + 1, self.add_button)

        if is_initial:
            self.add_button = QPushButton("+", self)  # 创建添加按钮
            self.add_button.clicked.connect(lambda: self.create_allinone_widget())  # 连接点击事件到addWidgets函数
            self.add_button.setStyleSheet(
                "QPushButton { background-color: #28A745; color: white; border: none; border-radius: 15px; padding: 12px 20px; font-size: 24px; }")
            widgetLayout.addWidget(self.add_button)  # 将添加按钮添加到水平布局

        self.groupLayout.addLayout(widgetLayout)  # 将水平布局添加到垂直布局

    def removeWidgetLayout(self, layout):
        index = self.groupLayout.indexOf(layout)  # 获取布局在垂直布局中的索引
        last_index = self.groupLayout.count() - 1  # 获取垂直布局中最后一个小部件的索引
        if index == last_index:
            last_layout = self.groupLayout.itemAt(index - 1).layout()  # 获取上一个布局
            last_layout.addWidget(self.add_button)  # 在上一个布局中添加添加按钮

        for i in reversed(range(layout.count())):
            widget = layout.itemAt(i).widget()  # 获取小部件
            if widget is not None:
                widget.deleteLater()  # 删除小部件
        layout.deleteLater()  # 删除布局

    def slot_check_task_done(self):
        print("\n\n=============== 当前线程数：", self.thread_num_remain)
        if self.search_thread_list:
            print('=============== 线程数 减1')
            self.thread_num_remain -= 1
            print('=============== 剩余线程数：', self.thread_num_remain)
            if self.thread_num_remain == 0:  # 所有线程都跑完了
                print('=============== 所有线程都跑完了！！')
                self.progress.close()
                self.slot_parse_data()
        else:
            if self.progress:
                self.progress.close()

    def parse_fofa_query(self, search_combo_box, line_edit):
        fofa_ip_search = ' ip="{}" '
        fofa_domain_search = ' domain="{}" '
        fofa_cname_search = ' cname="{}" '
        fofa_host_search = ' host=".{}" '
        fofa_cert_search = ' cert="{}" '
        fofa_port_search = ' port="{}" '
        fofa_country_search = ' country="{}" '
        fofa_title_search = ' title="{}" '
        fofa_body_search = ' body="{}" '
        fofa_header_search = ' header="{}" '
        fofa_org_search = ' org="{}" '
        query_str = ''

        if not search_combo_box:
            return ''
        query_type = search_combo_box.currentText().strip()
        if query_type == "":
            return ''
        if not line_edit:
            return ''
        content = line_edit.text().strip()
        if content == '':
            return ''

        if query_type == 'ip/段':
            query_str += fofa_ip_search.format(content)
        elif query_type == '域名':
            query_str += fofa_domain_search.format(content) + '||'
            query_str += fofa_cname_search.format(content) + '||'
            query_str += fofa_host_search.format(content) + '||'
            query_str += fofa_cert_search.format(content)
        elif query_type == '证书':
            query_str += fofa_cert_search.format(content)
        elif query_type == '端口':
            query_str += fofa_port_search.format(content)
        elif query_type == '国家':
            query_str += fofa_country_search.format(content)
        elif query_type == 'title':
            query_str += fofa_title_search.format(content)
        elif query_type == 'header':
            query_str += fofa_header_search.format(content)
        elif query_type == 'body':
            query_str += fofa_body_search.format(content)
        elif query_type == '组织':
            query_str += fofa_org_search.format(content)
        elif query_type == '自定义':
            try:
                content = content.split('fofa:')[1]
                query_str = content
            except:
                print('format error. it must like  fofa:header="123" || body="456" ')
        return query_str

    def parse_shodan_query(self, search_combo_box, line_edit):
        shodan_ip_search = 'ip:"{}"'
        shodan_net_search = 'net:"{}"'
        shodan_domain_search = '{}'
        shodan_host1_search = ' hostname="{}"'
        shodan_host2_search = ' hostname="*.{}"'
        shodan_cert_search = 'ssl:"{}"'
        shodan_port_search = 'port:"{}"'
        shodan_country_search = 'country:"{}"'
        shodan_title_search = 'http.title:"{}"'
        shodan_body_search = 'http.html="{}"'
        shodan_header_search = 'http.component:"Server" http.component.data:"{}"'
        shodan_org_search = 'org:"{}"'
        query_str = ''

        if not search_combo_box:
            return ''
        query_type = search_combo_box.currentText().strip()
        if query_type == "":
            return ''
        if not line_edit:
            return ''
        content = line_edit.text().strip()
        if content == '':
            return ''

        if query_type == 'ip/段':
            if '/' not in content:
                query_str += shodan_ip_search.format(content)
            else:
                query_str += shodan_net_search.format(content)
        elif query_type == '域名':
            query_str += shodan_domain_search.format(content) + '||'
            query_str += shodan_host1_search.format(content) + '||'
            query_str += shodan_host2_search.format(content)
        elif query_type == '证书':
            query_str += shodan_cert_search.format(content)
        elif query_type == '端口':
            query_str += shodan_port_search.format(content)
        elif query_type == '国家':
            query_str += shodan_country_search.format(content)
        elif query_type == 'title':
            query_str += shodan_title_search.format(content)
        elif query_type == 'header':
            query_str += shodan_header_search.format(content)
        elif query_type == 'body':
            query_str += shodan_body_search.format(content)
        elif query_type == '组织':
            query_str += shodan_org_search.format(content)
        elif query_type == '自定义':
            try:
                content = content.split('shodan:')[1]
                query_str = content
            except:
                print('format error. it must like  shodan:port:8080 ')
        return query_str.strip()

    def slot_parse_data(self):
        merge_dic = {}
        del self.merge_data_list
        del self.total_data_list
        self.merge_data_list = []
        self.total_data_list = []

        # 1.parse fofa data
        if window.fofa_page.fofa_current_data:
            for page in window.fofa_page.fofa_current_data:
                for row in page:
                    try:
                        host = row[0]
                        ip = row[1]
                        port = str(row[2])
                        title = row[3]
                        domain = row[4]
                        country = row[5]
                        protocol = row[6]
                        try:
                            if '://' not in host:
                                host = f'{protocol}://{host}'
                        except:
                            pass
                        server = row[7]
                        product = row[8]
                        last_update = row[9]
                        country_name = row[10]

                        fofa_single_record = {
                            "title": title,
                            "server": server,
                            "host": host,
                            "port": str(port),
                            "pro": protocol,
                            "ip": ip,
                            "product": product,
                            "city": country_name,
                            "code": country,
                            "update_time": last_update,
                            "domain": domain,
                            "vuln": '',
                            "os": "",
                            "org": "",
                            "isp": "",
                            "from": "fofa",
                            "vulns": "",
                        }

                        fofa_port_info = {
                            "host": f"{protocol}://{ip}:{port}",
                            "title": title,
                            "server": server,
                            "pro": protocol,
                            "product": product,
                            "update_time": last_update,
                            "from": "fofa",
                        }

                        fofa_record = {
                            "ports": {
                                str(port): fofa_port_info,
                            },
                            "ip": ip,
                            "city": country_name,
                            "code": country,
                            "domain": domain,
                            "vulns": '',
                            "os": "",
                            "org": "",
                            "isp": "",
                        }

                        self.total_data_list.append(fofa_single_record)

                        id = ip
                        _record = merge_dic.get(id)
                        if _record:
                            if _record.get('domain'):
                                try:
                                    _domain = _record.get('domain').split(',')
                                    if domain:
                                        _domain.append(domain)
                                        _domain = list(set(_domain))
                                        merge_dic[id]['domain'] = ",".join(_domain)
                                except:
                                    traceback.print_exc()

                            if _record['ports'].get(str(port)):
                                _port_info = _record['ports'][str(port)]
                                _date_str = _port_info['update_time']
                                current_record_date_str = last_update
                                date_format = ["%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S.%f"]
                                for _dindex, d_format in enumerate(date_format):
                                    try:
                                        _date = datetime.strptime(_date_str, d_format)
                                        break
                                    except:
                                        if _dindex + 1 == len(date_format):
                                            traceback.print_exc()
                                            print("\n\n\n[-] error date:", _date_str)
                                            _date = datetime.strptime("2010-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                                        else:
                                            continue

                                current_record_date = datetime.strptime(current_record_date_str, "%Y-%m-%d %H:%M:%S")
                                # 如果当前这条fofa记录里的测绘日期要比字典里存储的新（更大），则对字典里的记录进行更新，但只更新fofa数据集应有的字段，对fofa不具有的字段不要更新
                                if current_record_date > _date:
                                    # print('[+] fofa date new than')
                                    merge_dic[id]['ports'][port] = fofa_port_info
                                else:
                                    # print('[+] fofa date old ')
                                    # 当前的fofa记录更新日期比字典里的记录的日期更老，则只更新fofa特有而其他数据集没有的字段
                                    merge_dic[id]['ports'][port]['server'] = fofa_port_info['server']
                            else:
                                merge_dic[id]['ports'][port] = fofa_port_info
                        else:
                            merge_dic[id] = fofa_record


                    except:
                        traceback.print_exc()
        else:
            pass

        # 2.parse shodan data
        if window.shodan_page.shodan_current_data:
            for ip_info_list in window.shodan_page.shodan_current_data:
                for port_info_with_ip in ip_info_list:  # shodan的记录是ip上所有端口字典信息组成的列表， [ port1_dict, port2_dict ...]
                    ip_str = port_info_with_ip['ip_str'] if port_info_with_ip.get('ip_str') else ''
                    port_str = port_info_with_ip['port'] if port_info_with_ip.get('port') else ''
                    port_str = str(port_str)
                    domain_str = port_info_with_ip['domains'] if port_info_with_ip.get('domains') else ''
                    if domain_str: domain_str = ",".join(domain_str)

                    os_str = port_info_with_ip['os'] if port_info_with_ip.get('os') else ''
                    country_name_str = port_info_with_ip['location']['country_name'] if port_info_with_ip['location'][
                        'country_name'] else ''
                    country_code = port_info_with_ip['location']['country_code'] if port_info_with_ip['location'][
                        'country_code'] else ''
                    org_str = port_info_with_ip['org'] if port_info_with_ip.get('org') else ''
                    isp_str = port_info_with_ip['isp'] if port_info_with_ip.get('isp') else ''
                    hostnames = port_info_with_ip['hostnames'] if port_info_with_ip.get('hostnames') else ''
                    if hostnames: hostnames = ",".join(hostnames)
                    protocol = port_info_with_ip['_shodan']['module'] if port_info_with_ip.get('_shodan') else 'unknow'
                    last_update_date = port_info_with_ip.get('timestamp')

                    # 转换shodan的日期格式为 %Y-%m-%d %H:%M:%S ， 短一些
                    try:
                        probe_date = datetime.strptime(last_update_date, "%Y-%m-%dT%H:%M:%S.%f")
                        last_update_date = probe_date.strftime("%Y-%m-%d %H:%M:%S")
                    except:
                        pass

                    try:
                        title = port_info_with_ip['http']['title']
                    except:
                        title = ''
                    try:
                        product = port_info_with_ip['product']
                    except:
                        product = ''
                    try:
                        components = port_info_with_ip['http']['components']
                        components = ';'.join(key + ':' + ';'.join(components[key]['categories']) for key in components)
                    except:
                        components = ''

                    vuln_info = port_info_with_ip['vulns'] if port_info_with_ip.get('vulns') else {}
                    if vuln_info:  # 如果当前保存的记录中有漏洞记录，先把cve对应的端口记录上
                        for cve in port_info_with_ip['vulns']:
                            port_info_with_ip['vulns'][cve]['port'] = [port_str]
                        vuln_info = port_info_with_ip['vulns']

                    vulns_str = ''
                    try:
                        vulns = port_info_with_ip.get('vuln')
                        if vulns:
                            vulns_str = '\n'.join(
                                key + ':' + 'verified' if vulns[key]['verified'] else key + ':' + 'NoTest' for key in
                                vulns)
                    except:
                        traceback.print_exc()

                    shodan_single_record = {
                        "title": title,
                        "server": "",
                        "host": f'{protocol}://{ip_str}:{port_str}',
                        "port": int(port_str),
                        "pro": protocol,
                        "ip": ip_str,
                        "product": product + components if components else product,
                        "city": country_name_str,
                        "code": country_code,
                        "update_time": last_update_date,
                        "vuln": vulns_str,
                        "os": os_str,
                        "org": org_str,
                        "isp": isp_str,
                        "domain": domain_str + "," + hostnames,
                        "from": "shodan",
                        "vulns": vuln_info,
                    }

                    shodan_port_info = {
                        "host": f'{protocol}://{ip_str}:{port_str}',
                        "title": title,
                        "server": "",
                        "pro": protocol,
                        "product": product,
                        "update_time": last_update_date,
                        "from": "shodan",
                    }

                    shodan_record = {
                        "ports": {
                            str(port_str): shodan_port_info,
                        },
                        "ip": ip_str,
                        "city": country_name_str,
                        "code": country_code,
                        "domain": domain_str,
                        "vulns": vuln_info,
                        "os": os_str,
                        "org": org_str,
                        "isp": isp_str,
                    }

                    self.total_data_list.append(shodan_single_record)

                    id = ip_str
                    _record = merge_dic.get(id)
                    if _record:  # 如果merge字典中存在重复的一条 ip，开始比较更新日期等，并更新一些shodan独有的数据字段
                        # print('shodan处理流程,  字典里存在重复的一条 ip')
                        if _record.get('domain'):
                            try:
                                _domain = _record.get('domain').split(',')
                                if domain_str and hostnames:
                                    domains_str = domain_str + hostnames
                                    _domain.extend(domains_str.split(','))
                                    _domain = list(set(_domain))
                                    merge_dic[id]['domain'] = ",".join(_domain)
                            except:
                                traceback.print_exc()

                        try:
                            if not _record.get('vulns'):
                                merge_dic[id]['vulns'] = vuln_info
                            else:
                                for cve in vuln_info:
                                    try:
                                        if merge_dic[id].get('vulns') == '':
                                            merge_dic[id]['vulns'] = vuln_info
                                            break
                                        elif isinstance(merge_dic[id].get('vulns'), dict):
                                            if merge_dic[id]['vulns'].get(cve):
                                                merge_dic[id]['vulns'].get(cve)['port'].append(port_str)
                                            else:
                                                merge_dic[id]['vulns'][cve] = vuln_info[cve]
                                        else:
                                            print('[-] error: vulns is not dict')
                                    except:
                                        traceback.print_exc()
                                        print('\n\n==========\n\n')
                                        print(merge_dic[id].get('vulns'))
                            if _record.get('os') is None:
                                merge_dic[id]['os'] = os_str
                            if _record.get('isp') is None:
                                merge_dic[id]['isp'] = isp_str
                            if _record.get('org') is None:
                                merge_dic[id]['org'] = org_str

                            if _record['ports'].get(port_str):
                                _port_info = _record['ports'][port_str]
                                _date_str = _port_info['update_time']
                                current_record_date_str = last_update_date
                                _date = None
                                # 将日期时间字符串转换为日期时间对象
                                date_format = ["%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"]
                                for _dindex, d_format in enumerate(date_format):
                                    try:
                                        _date = datetime.strptime(_date_str, d_format)
                                        break
                                    except:
                                        if _dindex + 1 == len(date_format):
                                            traceback.print_exc()
                                            print("\n\n\n[-] error date:", _date_str)
                                            _date = datetime.strptime("2010-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")
                                        else:
                                            continue
                                try:
                                    current_record_date = datetime.strptime(current_record_date_str,
                                                                            "%Y-%m-%dT%H:%M:%S.%f")
                                except:
                                    current_record_date = datetime.strptime(current_record_date_str,
                                                                            "%Y-%m-%d %H:%M:%S")
                                # 如果当前这条shodan记录里的测绘日期要比字典里存储的新（更大），则对字典里的记录进行更新
                                # 但只更新shodan数据集应有的字段，对shodan不具有的字段不要更新
                                if _date:
                                    if current_record_date > _date:
                                        # print('[+] shodan date new than')
                                        for key, value in shodan_port_info.items():
                                            if value:
                                                merge_dic[id]['ports'][port_str][key] = value
                                else:
                                    # 如果当前这条shodan记录里的测绘日期要比字典里存储的老，则只对shodan特有的字段进行更新
                                    pass
                            else:
                                merge_dic[id]['ports'][port_str] = shodan_port_info
                        except:
                            traceback.print_exc()
                    else:
                        # print('shodan处理流程,  字典里没有重复ip')
                        merge_dic[id] = shodan_record

        for i in merge_dic.keys():
            self.merge_data_list.append(merge_dic[i])


        with open('output_tmp.json', 'w', encoding='utf-8', errors='ignore') as f:
            for i in self.merge_data_list:
                f.write(json.dumps(i))
                f.write('\n')

        # 4.show page
        self.view_page = data_view.DataDisplay(self.merge_data_list)
        self.view_page_list.append(self.view_page)
        self.view_page.setWindowState(self.view_page.windowState() | Qt.WindowMaximized)  # 设置窗口为最大化模式，不覆盖任务栏
        self.view_page.show()

    def slot_search(self):
        '''点击搜索按钮触发'''
        del self.search_thread_list
        del self.total_data_list
        del self.merge_data_list
        self.total_data_list = []
        self.merge_data_list = []
        self.search_thread_list = []
        self.thread_num_remain = 0

        fofa_statement_text = ''
        shodan_statement_text = ''
        condition_count = self.groupLayout.count()
        datacenter_list = [
            'fofa',
            'shodan',
        ]

        # 创建进度条
        self.progress = Qprogressbar()
        self.progress.setModal(True)
        self.progress.show()

        datacenter_num = len(datacenter_list)
        # 解析搜索语句
        for db_index, datacenter in enumerate(datacenter_list):
            print('current datacenter:', datacenter)
            for condition_index in range(condition_count):
                try:
                    sub_groupLayout = self.groupLayout.itemAt(condition_index).layout()  # 获取垂直布局中的水平布局

                    search_combo_box = None
                    relation_combo_box = None
                    line_edit = None

                    for i in range(sub_groupLayout.count()):  # 遍历水平布局中的小部件
                        item = sub_groupLayout.itemAt(i)
                        try:
                            obj = item.widget()
                        except:
                            continue
                        if obj:
                            if obj.objectName() == 'search_type':  # 搜索类型（字段）下拉菜单
                                search_combo_box = obj
                            elif obj.objectName() == 'condition':  # 搜素条件（即语句）文本框
                                line_edit = obj
                            elif obj.objectName() == 'relationship':  # 逻辑关系下拉菜单
                                relation_combo_box = obj

                    # if search_combo_box and relation_combo_box and line_edit:
                    #     print(f"第{condition_index + 1}行 搜索字段: {search_combo_box.currentText()}, 逻辑关系: {relation_combo_box.currentText()}, 文本: {line_edit.text()}")
                    #
                    # elif search_combo_box and line_edit:
                    #     print(f"第{condition_index + 1}行 搜索字段: {search_combo_box.currentText()}, 文本: {line_edit.text()}")
                    # else:
                    #     print("找不到组件")

                    if condition_index == condition_count - 1:  # end line do not need append '||'
                        if datacenter == 'fofa':
                            new_condition = self.parse_fofa_query(search_combo_box, line_edit)
                            if new_condition:
                                fofa_statement_text += new_condition
                        elif datacenter == 'shodan':
                            new_condition = self.parse_shodan_query(search_combo_box, line_edit)
                            if new_condition:
                                shodan_statement_text += new_condition
                    else:
                        if datacenter == 'fofa':
                            new_condition = self.parse_fofa_query(search_combo_box, line_edit)
                            if new_condition:
                                fofa_statement_text += new_condition
                                fofa_statement_text += '||'
                        elif datacenter == 'shodan':
                            new_condition = self.parse_shodan_query(search_combo_box, line_edit)
                            if new_condition:
                                shodan_statement_text += new_condition
                                shodan_statement_text += '||'
                except Exception as e:
                    print(e)
            # parse query statement done.

            # check query statement
            if datacenter == 'fofa':
                print('[+] fofa search:', fofa_statement_text)
                if fofa_statement_text.strip() == '':
                    print('[-] error, check your input')
                    if self.search_thread_list == []:  # 如果没有任何引擎正在搜索
                        if db_index + 1 < datacenter_num:  # 如果所有的搜索引擎还没有遍历完，继续
                            continue
                        elif db_index + 1 == datacenter_num:  # 所有搜索引擎已经遍历完，告诉用户：输入错误
                            self.progress.close()
                            QMessageBox.information(self, "错误",
                                                    "error, 请检查你的输入")
                            return
                    else:
                        if db_index + 1 == datacenter_num:  # 如果所有搜索引擎已经遍历完
                            break
                        else:
                            continue  # 搜索引擎还没有遍历完，继续遍历


            elif datacenter == 'shodan':
                print(shodan_statement_text)
                print('[+] shodan search:', shodan_statement_text)

                if shodan_statement_text.strip() == '':
                    print('[-] error, check your input')
                    if self.search_thread_list == []:  # 如果没有任何引擎正在搜索
                        if db_index + 1 < datacenter_num:  # 如果所有的搜索引擎还没有遍历完，继续
                            continue
                        elif db_index + 1 == datacenter_num:  # 所有搜索引擎已经遍历完，告诉用户：输入错误
                            self.progress.close()
                            QMessageBox.information(self, "错误",
                                                    "error, 请检查你的输入")
                            return
                    else:
                        if db_index + 1 == datacenter_num:  # 如果所有搜索引擎已经遍历完
                            break
                        else:  # 搜索引擎还没有遍历完，继续遍历
                            continue

            if datacenter == 'fofa':
                qbase64 = base64.b64encode(fofa_statement_text.encode('utf-8')).decode('ascii')
                num = window.fofa_page.num_select_combo.currentText()
                query_url = 'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&page={}&size={}&fields=host,ip,port,title,domain,country,protocol,server,product,lastupdatetime,country_name'.format(
                    config_dic['fofa']['fofa_mail'], config_dic['fofa']['fofa_key'],
                    qbase64, '1', num)
                if window.fofa_page.search_thread:
                    print('[-] error, fofa查询线程正在运行，请等待结束后再使用快捷查询')
                    QMessageBox.information(self, "错误",
                                            "error, fofa查询线程正在运行，请等待结束后再使用快捷查询")
                    return
                self.fofa_search_thread = FofaSearchThread(url=query_url)
                self.fofa_search_thread.finished.connect(lambda html: window.fofa_page.slot_draw_table(html))
                self.search_thread_list.append(self.fofa_search_thread)
                self.thread_num_remain += 1

            elif datacenter == 'shodan':
                querys = ''
                if '||' in shodan_statement_text:
                    try:
                        querys = shodan_statement_text.strip().split('||')
                    except:
                        print('[-] error, 请检查你的输入')
                        QMessageBox.information(self, "错误",
                                                "error， 请检查你的输入")
                        return
                else:
                    querys = shodan_statement_text

                self.shodan_api_key = config_dic['shodan']['shodan_api']
                search_host = querys
                page = 1
                self.api = shodan.Shodan(self.shodan_api_key, proxies=g_proxies)
                self.shodan_search_type = 'Host'
                try:
                    self.shodan_search_limit_per_page = int(
                        window.shodan_page.api_limit_input.text()) if window.shodan_page.api_limit_input.text() else 1000
                except:
                    traceback.print_exc()
                _note = search_host if isinstance(search_host, str) else ",".join(search_host)
                window.shodan_page.log_display.append(f'正在查询:  {_note} ...' + '\n')
                QApplication.processEvents()  # 刷新页面，显示正在查询

                args = {
                    'api': self.api,
                    'shodan_search_limit_per_page': self.shodan_search_limit_per_page,
                    'page': page,
                    'shodan_search_type': self.shodan_search_type,
                    'search_host': search_host,
                    'need_view': True,
                }

                if window.shodan_page.search_thread:
                    print('searching now.. not over')
                    print('[-] error, shodan查询线程正在运行，请等待其结束再查询')
                    QMessageBox.information(self, "错误",
                                            "error, shodan查询线程正在运行，请等待其结束再查询")
                    return
                else:
                    print('search thread start..')
                    self.shodan_search_thread = ShodanSearchThread(args)
                    self.shodan_search_thread.finished.connect(
                        lambda results: window.shodan_page.slot_draw_table(results))
                    self.search_thread_list.append(self.shodan_search_thread)
                    if isinstance(search_host, str):
                        self.thread_num_remain += 1
                    else:
                        self.thread_num_remain += len(search_host)

        # For end. Now start thread
        print(' ........... [+] All thread remain is :', self.thread_num_remain)
        threads_num = len(self.search_thread_list)
        if threads_num == 0:
            self.progress.close()
            return
        else:
            print("真实线程数：", len(self.search_thread_list))

            for t_index, t in enumerate(self.search_thread_list):
                # t.finished.connect(self.signal_task_done)
                t.start()

        # if self.last_search_thread.isFinished():
        #     self.progress.close()
        #     self.slot_parse_data()


class FofaSearchThread(QThread):
    # 自定义信号，用于发送请求结果
    finished = pyqtSignal(object)  # object表示可以传递任何类型的参数

    def __init__(self, url):
        super().__init__()  # 显式调用父类的构造函数。这确保了父类的初始化逻辑也被执行，否则不会执行
        self.name = 'fofa'
        self.url = url

    def run(self):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0"}
        html = None
        print(self.url)
        fofa_proxy = config_dic['proxies'] if config_dic['is_fofa_use_proxy'] == '1' else {}
        # 发送 HTTP 请求
        try:
            html = requests.get(url=self.url, headers=headers, verify=False, timeout=120, proxies=fofa_proxy)
            html = html.json()
        except Exception as e:
            traceback.print_exc()
        print('[+] +++++++++++++ fofa emit ')
        self.finished.emit(html)  # emit只需要一次，不论emit时带不带参数，所有被绑定的槽函数都会被执行，不论是带参数的槽函数，还是不带参数的槽函数


class ShodanSearchThread(QThread):
    # 自定义信号，用于发送请求结果
    finished = pyqtSignal(object)  # object表示可以传递任何类型的参数. 用来触发shodan页面绘制表格
    close_progress_bar = pyqtSignal()  # 用来触发快捷搜索页面的进度条关闭
    signal_to_view = pyqtSignal()  # 用来触发融合查询的展示界面开始绘图

    def __init__(self, args):
        super().__init__()  # 显式调用父类的构造函数。这确保了父类的初始化逻辑也被执行，否则不会执行
        self.name = 'shodan'
        self.shodan_api = args['api']
        self.page = args['page']
        self.search_host = args['search_host']
        self.shodan_search_limit_per_page = args['shodan_search_limit_per_page']
        self.shodan_search_type = args['shodan_search_type']
        self.need_view = False
        if args.get('need_view') == True:
            self.need_view = True

    def run(self):
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:81.0) Gecko/20100101 Firefox/81.0"}
        # 发送 HTTP 请求
        limit = self.shodan_search_limit_per_page
        results = None
        if self.shodan_search_type == 'Host':
            print('[+] Shodan searching...')
            if isinstance(self.search_host, str):
                try:
                    fields = 'ip_str,port,domains,os,http.title,country,org,isp,timestamp,product,vulns,components,location,_shodan.module'.split(
                        ',')
                    offset = 0 if int(self.page) == 1 else limit * (int(self.page) - 1)
                    results = self.shodan_api.search(self.search_host, page=int(self.page),
                                                     minify=False, limit=limit, offset=offset,
                                                     fields=fields)  # 搜索apache，返回 JSON格式的数据
                    print('-------------------------------------------------------------')
                    print("shodan1共搜索到{}条记录".format(results.get('total')))
                    # print(results)
                except:
                    traceback.print_exc()
            elif isinstance(self.search_host, list):
                for query_str in self.search_host:
                    try:
                        fields = 'ip_str,port,domains,os,http.title,country,org,isp,timestamp,product,vulns,components,location,_shodan.module'.split(
                            ',')
                        offset = 0 if int(self.page) == 1 else limit * (int(self.page) - 1)
                        results = self.shodan_api.search(query_str, page=int(self.page),
                                                         minify=False, limit=limit, offset=offset,
                                                         fields=fields)  # 搜索apache，返回 JSON格式的数据
                        print('-------------------------------------------------------------')
                        print("shodan2共搜索到{}条记录".format(results.get('total')))
                        # print(results)
                        self.finished.emit(results)
                        print('[+] +++++++++++++ shodan emit1')
                    except:
                        traceback.print_exc()
                        print('[+] +++++++++++++ shodan emit3')
                        self.finished.emit(None)
                # self.close_progress_bar.emit()
                # self.finished.emit()
                return
        else:
            print('other func is in working..')
        self.finished.emit(results)
        print('[+] +++++++++++++ shodan emit2')
        self.close_progress_bar.emit()


class FofaPage(QWidget):
    signal_data_ok = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.search_thread = None
        self.current_table_line = 0
        self.fofa_current_query = ''
        self.fofa_total_page = 0
        self.fofa_current_page = 0
        self.fofa_current_data = []

        self.init_ui()
        self.set_style()
        self.set_connect()

    def init_ui(self):
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 20, 0, 0)  # 设置左边，顶部，右边，底部间距

        # 第一行：fofa语法输入框和选项
        fofa_syntax_layout = QHBoxLayout()
        fofa_syntax_label = QLabel("fofa语法: ")
        self.fofa_statement_input = QLineEdit()
        find_number_label = QLabel("查询数量: ")
        self.num_select_combo = QComboBox()
        self.num_select_combo.addItems(["10000", "5000", "2000", "1000", "100"])
        self.search_button = QPushButton("查询")

        # 使用 addWidget 方法将指定控件 添加到布局fofa_syntax_layout中
        fofa_syntax_layout.addWidget(fofa_syntax_label)
        fofa_syntax_layout.addWidget(self.fofa_statement_input)
        fofa_syntax_layout.addWidget(find_number_label)
        fofa_syntax_layout.addWidget(self.num_select_combo)
        fofa_syntax_layout.addWidget(self.search_button)

        operate = QHBoxLayout()
        self.export_button = QPushButton("导出数据")
        self.clear_result_button = QPushButton("清空结果")
        self.clear_log_button = QPushButton("清空日志")

        # 第二行：搜索结果显示
        operate.addWidget(self.export_button)
        operate.addWidget(self.clear_result_button)
        operate.addWidget(self.clear_log_button)
        operate.addStretch(1)

        # 第三行：表格展示和日志显示
        table_and_log_layout = QHBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(11)
        self.result_table.setHorizontalHeaderLabels(
            ["Host", "IP", "Port", "协议", "产品", "标题", "server", "area", "域名", "国家", "更新时间"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 列自动调整以填充整个可用的水平空间
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置双击表格时不能编辑
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)  # 可鼠标调整列宽

        self.log_display = QTextEdit()
        self.log_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        table_and_log_layout.addWidget(self.result_table)
        table_and_log_layout.addWidget(self.log_display)

        # 第四行：搜索结果显示
        result_info_layout = QHBoxLayout()
        self.result_info_label = QLabel("搜索结果共0条，共0页")
        result_info_layout.addWidget(self.result_info_label)
        result_info_layout.addStretch(
            1)  # addStretch()是 PyQt 中用于布局管理的一个方法。在这个方法中，参数 1 表示一个拉伸因子，它会在布局中创建一个可拉伸的空间。这个空间会占据布局中剩余的可用空间，将其他部件推到布局的一端，从而实现布局的对齐或者调整

        # addLayout作用为将名为fofa_syntax_layout等的布局添加到名为 layout 的主布局中。
        layout.addLayout(fofa_syntax_layout)
        layout.addSpacing(20)  # 给整体页面的垂直布局（上下之间）插入20px的空白间隔
        layout.addLayout(operate)
        layout.addSpacing(20)  # 给整体页面的垂直布局（上下之间）插入20px的空白间隔
        layout.addLayout(table_and_log_layout)
        layout.addLayout(result_info_layout)

        self.setLayout(layout)

    def set_style(self):
        self.button_style = button_style
        self.height_1 = "height: 40px"
        self.height_width_1 = "height: 30px; width: 150px;"
        self.input_style = "border-radius: 13px;height: 35px; border: 1px solid gray"

        # 第一行
        self.search_button.setStyleSheet(self.button_style + self.height_width_1)
        self.fofa_statement_input.setStyleSheet(self.input_style)
        combo_box_style = """
                QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
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
        self.num_select_combo.setStyleSheet(combo_box_style)

        # 第三行 导出按钮，清空日志按钮
        self.export_button.setStyleSheet(self.button_style + self.height_1)
        self.clear_result_button.setStyleSheet(self.button_style + self.height_1)
        self.clear_log_button.setStyleSheet(self.button_style + self.height_1)

        # 为按钮设置光标样式为手型
        self.clear_result_button.setCursor(Qt.PointingHandCursor)
        self.clear_log_button.setCursor(Qt.PointingHandCursor)
        self.export_button.setCursor(Qt.PointingHandCursor)
        self.search_button.setCursor(Qt.PointingHandCursor)

    def set_connect(self):
        # 绑定查询按钮点击事件
        self.search_button.clicked.connect(self.slot_search)
        self.export_button.clicked.connect(self.slot_export_data)
        self.clear_result_button.clicked.connect(self.slot_clear_result_table)
        self.clear_log_button.clicked.connect(self.slot_clear_log_display)

    def slot_draw_table(self, html):
        '''查询成功后触发'''
        if html == None:
            self.log_display.append('访问fofa时网络异常：' + '\n' + '-' * 29)
            self.search_thread = None
            self.signal_data_ok.emit()
            return
        if 'errmsg' not in html.keys():
            try:
                results = html["results"]
                result = html  # 将str类型的数据转换为dict类型
                num = self.num_select_combo.currentText()
                size = result['size']  # 转为dict然后查询
                print('-------------------------------------------------------------')
                print("fofa共搜索到{}条记录, 本次获取了其中的{}条！".format(size, len(results)))

                if self.fofa_total_page == 0:
                    if size <= int(num):
                        self.fofa_total_page = 1
                    else:
                        left = size % int(num)
                        if left > 0:
                            left = 1
                        else:
                            left = 0
                        self.fofa_total_page = int(size / int(num)) + left

                self.result_info_label.setText(
                    '共' + str(size) + ' ' + '条, 共 ' + str(self.fofa_total_page) + '页, ' + '当前第' + str(
                        self.fofa_current_page) + '页')

                self.log_display.append('已找到：' + str(size) + ' ' + '条结果' + '\n')
                QApplication.processEvents()  # 刷新界面
                self.log_display.append('查询状态：完成' + '\n' + '-' * 29)

                # print(result['results'])
                # print(result)

                self.fofa_current_data.append(result['results'])

                for link in result['results']:
                    host = link[0]
                    ip = link[1]
                    port = link[2]
                    title = link[3]
                    domain = link[4]
                    country = link[5]
                    protocol = link[6]
                    try:
                        if '://' not in host:
                            host = f'{protocol}://{host}'
                    except:
                        pass
                    server = link[7]
                    product = link[8]
                    last_update = link[9]
                    country_name = link[10]

                    col_name = ["Host", "IP", "Port", "协议", "产品", "标题", "server", "area", "域名", "国家",
                                "更新时间"]
                    column_mapping = {}
                    for index, col in enumerate(col_name):
                        column_mapping[index] = col

                    self.add_row_to_table([
                        host,
                        ip,
                        port,
                        protocol,
                        product,
                        title,
                        server,
                        country,
                        domain,
                        country_name,
                        last_update,
                    ], column_mapping)
            except:
                traceback.print_exc()
            # end For
        else:
            self.log_display.append('错误：' + str(html) + '\n' + '-' * 29)
        self.search_thread = None
        self.signal_data_ok.emit()

    def add_row_to_table(self, data: list, column_mapping: dict):
        row = self.result_table.rowCount()  # 获取当前行数
        self.result_table.insertRow(row)  # 插入新行

        for column, value in enumerate(data):
            item = QTableWidgetItem()
            item.setText(str(value))  # 设置单元格中的内容
            item.setToolTip(str(value))  # 设置鼠标悬浮在单元格上时浮现的内容
            mapped_column = column_mapping.get(column, None)
            if mapped_column:
                self.result_table.setItem(row, column, item)
            # 设置列宽可调整, 设置水平头部拉伸模式为Interactive

    def slot_search(self):
        '''点击搜索按钮触发'''
        self.log_display.append("正在查询...")
        QApplication.processEvents()  # 刷新界面，立即显示上面的插入，否则会等查询结束才显示
        # 获取下拉列表的值
        num_select_value = self.num_select_combo.currentText()

        # 获取输入框的文本值
        fofa_statement_text = self.fofa_statement_input.text()

        # 在这里可以使用获取到的值进行查询操作或者其他操作
        print("下拉列表的值:", num_select_value)
        print("输入框的值:", fofa_statement_text)
        if fofa_statement_text == '':
            print('错误：查询语句为空')
            self.log_display.append('错误：查询语句为空' + '\n')
            return

        # 查询过程
        if self.fofa_current_query == '':
            self.fofa_current_query = fofa_statement_text
        elif self.fofa_current_query != fofa_statement_text:
            self.fofa_current_page = 0
            self.fofa_total_page = 0
            self.fofa_current_query = fofa_statement_text

        if self.fofa_current_page != 0 and self.fofa_current_page == self.fofa_total_page:
            self.log_display.append('已获取了当前查询语句的所有结果！！！' + '\n')
            QApplication.processEvents()  # 刷新界面
            return
        self.fofa_current_page += 1

        qbase64 = base64.b64encode(fofa_statement_text.encode('utf-8')).decode('ascii')
        num = int(num_select_value)
        query_url = 'https://fofa.info/api/v1/search/all?email={}&key={}&qbase64={}&page={}&size={}&fields=host,ip,port,title,domain,country,protocol,server,product,lastupdatetime,country_name'.format(
            config_dic['fofa']['fofa_mail'], config_dic['fofa']['fofa_key'],
            qbase64, self.fofa_current_page, num)

        if self.search_thread:
            print('searching now.. not over')
        else:
            self.search_thread = FofaSearchThread(query_url)
            self.search_thread.finished.connect(self.slot_draw_table)
            self.search_thread.start()

    def slot_export_data(self):
        # 弹出文件对话框，选择导出文件路径
        file_path, _ = QFileDialog.getSaveFileName(self, "导出数据", "", "CSV Files (*.csv)")
        if file_path:
            # export_thread = threading.Thread(target=self.t_export_csv, args=(file_path,))
            # export_thread.start()
            self.log_display.append("正在导出...")

            # 禁用界面更新，防止频繁的界面刷新
            QApplication.instance().setOverrideCursor(Qt.WaitCursor)

            # 打开 CSV 文件，使用逗号分隔符
            with open(file_path, 'w', newline='', encoding='utf-8', errors='ignore') as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                # 写入表头
                headers = [self.result_table.horizontalHeaderItem(col).text() for col in
                           range(self.result_table.columnCount())]
                writer.writerow(headers)
                # 写入数据
                for page in self.fofa_current_data:
                    for row in page:
                        try:
                            host = row[0]
                            ip = row[1]
                            port = row[2]
                            title = row[3]
                            domain = row[4]
                            country = row[5]
                            protocol = row[6]
                            try:
                                if '://' not in host:
                                    host = f'{protocol}://{host}'
                            except:
                                pass
                            server = row[7]
                            product = row[8]
                            last_update = row[9]
                            country_name = row[10]
                            writer.writerow(
                                [
                                    host,
                                    ip,
                                    port,
                                    protocol,
                                    product,
                                    title,
                                    server,
                                    country,
                                    domain,
                                    country_name,
                                    last_update
                                ]
                            )
                        except:
                            traceback.print_exc()
                self.log_display.append("结果导出成功")

            # 恢复界面状态
            QApplication.instance().restoreOverrideCursor()

    def slot_clear_result_table(self):
        # 清空表格内容
        self.result_table.clearContents()
        self.result_table.setRowCount(0)  # 清空行数
        del self.fofa_current_data  # 清空列表，立即触发垃圾回收机制释放内存
        self.fofa_current_data = []
        self.fofa_current_page = 0
        self.fofa_total_page = 0

    def slot_clear_log_display(self):
        # 清空日志显示框内容
        self.log_display.setPlainText('')


class ShodanPage(QWidget):
    signal_data_ok = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_page_num = 0
        self.shodan_api_key = None
        self.api = None
        self.shodan_search_type = 'Host'
        self.shodan_search_limit_per_page = 1000
        self.search_thread = None
        self.shodan_current_data = []
        self.shodan_current_query = ''
        self.total_page = 0
        self.search_thread_list = []
        self.mutex = QMutex()

        self.init_ui()
        self.set_style()
        self.set_connect()

    def init_ui(self):
        # 创建布局
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 20, 0, 0)  # 设置左边，顶部，右边，底部间距

        # 第一行：语法输入框、请求方式下拉列表和查询按钮
        syntax_layout = QHBoxLayout()
        syntax_label = QLabel("shodan语法:")
        self.syntax_input = QLineEdit()

        self.find_button = QPushButton("查询")

        syntax_layout.addWidget(syntax_label)
        syntax_layout.addWidget(self.syntax_input)

        syntax_layout.addWidget(self.find_button)

        # 第二行：导出、清空结果、清空日志按钮、搜索结果和页码信息
        button_result_layout = QHBoxLayout()
        type_label = QLabel("请求方式: ")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Host", ])

        api_limit_label = QLabel("每页记录数: ")
        self.api_limit_input = QLineEdit("1000")

        button_layout = QHBoxLayout()

        self.export_button = QPushButton("导出结果")
        self.clear_result_button = QPushButton("清空结果")
        self.clear_log_button = QPushButton("清空日志")

        # 添加部件到布局中
        button_layout.addWidget(type_label, 0)  # 拉伸因子设为 0，意味着这个部件不会随着布局的改变而拉伸。而将下拉框的拉伸因子设为 1，使得它能够在布局中拉伸以填充剩余的空间。
        button_layout.addWidget(self.type_combo, 1)  # 指定 self.type_combo 的拉伸因子为 1

        button_layout.addSpacing(20)  # 添加20px长度的空白间隔
        button_layout.addWidget(api_limit_label, 0)
        button_layout.addWidget(self.api_limit_input, 0)

        button_layout.addStretch(1)  # 添加一个弹簧，使得后面的部件靠右对齐
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.clear_result_button)
        button_layout.addWidget(self.clear_log_button)

        # 将按钮布局和搜索结果布局添加到同一水平布局中
        button_result_layout.addLayout(button_layout)

        # 第四行：表格和日志显示
        table_log_layout = QHBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(15)
        self.result_table.setHorizontalHeaderLabels(
            ["IP", "Port", "协议", "产品", "标题", "组件", "漏洞", "域名", "hostname", "组织", "系统", "国家", "area",
             "isp", "更新时间"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 列自动调整以填充整个可用的水平空间
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)  # 可鼠标调整列宽

        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置双击表格时不能编辑
        self.log_display = QTextEdit()
        self.log_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        table_log_layout.addWidget(self.result_table)
        table_log_layout.addWidget(self.log_display)

        # 搜索结果和页码信息布局
        result_layout = QHBoxLayout()
        self.result_label = QLabel("搜索结果共0条，页码：")
        self.page_input = QLineEdit()

        result_layout.addWidget(self.result_label)
        result_layout.addWidget(self.page_input)

        # 调整页码输入框的位置
        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)  # 创建一个可伸缩的空间
        result_layout.addItem(spacer)  # 添加空间以推动页码输入框靠右
        result_layout.addLayout(result_layout)

        # 添加所有行到主布局中
        layout.addLayout(syntax_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(button_result_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(table_log_layout)
        layout.addLayout(result_layout)

        self.setLayout(layout)

    def set_style(self):
        self.button_style = button_style + "height: 40px;width: 130px;"
        # 第一行：语法输入框、请求方式下拉列表和查询按钮
        self.find_button.setStyleSheet(self.button_style)
        self.syntax_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.api_limit_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")

        self.type_combo.setStyleSheet("""
            QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
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
        """)
        # 第二行：导出、清空结果、清空日志按钮、搜索结果和页码信息
        self.export_button.setStyleSheet(self.button_style)
        self.clear_result_button.setStyleSheet(self.button_style)
        self.clear_log_button.setStyleSheet(self.button_style)

        self.page_input.setFixedWidth(100)  # 固定输入框宽度
        self.page_input.setStyleSheet(
            """
            border-radius: 13px;
            height: 30px;
            width: 150px;
            border: 1px solid gray;
            """
        )

    def set_connect(self):
        # 绑定查询按钮点击事件
        self.find_button.clicked.connect(self.slot_search)
        self.export_button.clicked.connect(self.export_data)
        self.clear_result_button.clicked.connect(self.clear_result_table)
        self.clear_log_button.clicked.connect(self.clear_log_display)

    def add_row_to_table(self, data: list, column_mapping: dict):
        self.mutex.lock()

        row = self.result_table.rowCount()  # 获取当前行数
        self.result_table.insertRow(row)  # 插入新行

        for column, value in enumerate(data):
            item = QTableWidgetItem()
            item.setText(str(value))  # 设置单元格中的内容
            item.setToolTip(str(value))  # 设置鼠标悬浮在单元格上时浮现的内容
            mapped_column = column_mapping.get(column, None)
            if mapped_column:
                self.result_table.setItem(row, column, item)
        self.mutex.unlock()

    def slot_draw_table(self, results):
        '''查询成功后触发'''
        if results is None:
            self.log_display.append('请求错误, result为空' + '\n' + '-' * 29)
            self.search_thread = None
            self.signal_data_ok.emit()
            return
        if not results.get('total'):
            self.log_display.append('查询结果为空' + '\n' + '-' * 29)
            self.signal_data_ok.emit()
            return
        if results.get('total') == 0:
            self.log_display.append('结果为0条' + '\n' + '-' * 29)
            self.signal_data_ok.emit()
            return
        print("Results found:" + str(results['total']))
        total = str(results['total'])
        if results['total'] <= self.shodan_search_limit_per_page:
            rest_page = 1
        else:
            left = results['total'] % self.shodan_search_limit_per_page
            if left != 0: left = 1
            rest_page = int(results['total'] / self.shodan_search_limit_per_page) + left

        self.result_label.setText('搜索结果共' + total + ' ' + '条, 共 ' + str(rest_page) + '页' + ', 当前第' + str(
            self.current_page_num) + '页 ')
        self.log_display.append('已找到：' + total + ' 条结果' + '\n')
        self.shodan_current_data.append(results['matches'])
        self.signal_data_ok.emit()

        # ["IP", "Port", "协议", "产品", "标题", "组件", "漏洞", "域名", "hostname", "组织", "系统", "国家", "area", "isp", "更新时间"]
        column_mapping = {
            0: "IP",
            1: "Port",
            2: "协议",
            3: "产品",
            4: "标题",
            5: "组件",
            6: "漏洞",
            7: "域名",
            8: "hostname",
            9: "组织",
            10: "系统",
            11: "国家",
            12: "area",
            13: "isp",
            14: "更新时间"
        }

        for result in results['matches']:
            ip_str1 = result['ip_str'] if result.get('ip_str') else ''
            port1 = result['port'] if result.get('port') else ''
            domains1 = result['domains'] if result.get('domains') else ''
            if domains1: domains1 = ",".join(domains1)

            os1 = result['os'] if result.get('os') else ''
            country_name1 = result['location']['country_name'] if result['location']['country_name'] else ''
            area_code_shodan = result['location']['country_code'] if result['location']['country_code'] else ''
            org1 = result['org'] if result.get('org') else ''
            isp1 = result['isp'] if result.get('isp') else ''
            hostnames = result['hostnames'] if result.get('hostnames') else ''
            if hostnames: hostnames = ",".join(hostnames)

            protocol = result['_shodan']['module'] if result.get('_shodan') else 'unknow'
            timestamp1 = result.get('timestamp')

            try:
                title = result['http']['title']
            except:
                title = ''
            try:
                product = result['product']
            except:
                product = ''
            try:
                components = result['http']['components']
                components = '\n'.join(key + ':' + ';'.join(components[key]['categories']) for key in components)
            except:
                components = ''

            try:
                vulns = result['vulns']
                vulns = '\n'.join(
                    key + ':' + 'verified' if vulns[key]['verified'] else key + ':' + 'NoTest' for key in
                    vulns)
            except:
                vulns = ''

            # ["IP", "Port", "协议", "产品", "标题", "组件", "漏洞", "域名", "hostname", "组织", "系统", "国家", "area", "isp", "更新时间"]
            self.add_row_to_table([
                ip_str1,
                port1,
                protocol,
                product,
                title,
                components,
                vulns,
                domains1,
                hostnames,
                org1,
                os1,
                country_name1,
                area_code_shodan,
                isp1,
                timestamp1
            ], column_mapping)

        self.search_thread = None

    def slot_search(self):
        '''点击搜索按钮触发'''
        # 获取下拉列表的值
        num_select_value = self.type_combo.currentText()

        # 获取输入框的文本值
        shodan_syntax_text = self.syntax_input.text()
        if shodan_syntax_text == '':
            print('错误：查询语句为空')
            self.log_display.append('错误：查询语句为空' + '\n')
            return

        try:
            self.current_page_num = int(self.page_input.text())
        except:
            # 如果用户没有手动指定需要查询的页数，则从第1页查起，每次点击就会自动查询下一页
            if self.shodan_current_query == '':  # 如果是初始状态或已重置的状态后的第一次查询
                self.shodan_current_query = shodan_syntax_text
            elif self.shodan_current_query != shodan_syntax_text:  # 如果历史查询语句存在，且用户重新输入了和之前不一样的检索语句，则基于新的语句从第1页开始查起
                self.current_page_num = 0
                self.total_page = 0
                self.shodan_current_query = shodan_syntax_text

        if self.total_page != 0 and self.total_page == self.current_page_num:
            self.log_display.append('已获取了当前查询语句的所有结果！！！' + '\n')
            return
        self.current_page_num += 1

        # 在这里可以使用获取到的值进行查询操作或者其他操作
        print("请求方式的值:", num_select_value)
        print("语法输入框的值:", shodan_syntax_text)

        self.shodan_api_key = config_dic['shodan']['shodan_api']
        search_host = shodan_syntax_text
        page = self.current_page_num
        self.api = shodan.Shodan(self.shodan_api_key, proxies=g_proxies)
        self.shodan_search_type = self.type_combo.currentText()
        try:
            self.shodan_search_limit_per_page = int(self.api_limit_input.text()) if self.api_limit_input.text() else 500
        except:
            traceback.print_exc()
        self.log_display.append(f'正在查询:  {search_host} ...' + '\n')
        QApplication.processEvents()  # 刷新页面，显示正在查询

        args = {
            'api': self.api,
            'shodan_search_limit_per_page': self.shodan_search_limit_per_page,
            'page': page,
            'shodan_search_type': self.shodan_search_type,
            'search_host': search_host,
        }

        if self.search_thread:
            print('searching now.. not over')
        else:
            print('search thread start..')
            self.search_thread = ShodanSearchThread(args)
            self.search_thread.finished.connect(self.slot_draw_table)
            self.search_thread.start()

    def export_data(self):
        # 弹出文件对话框，选择导出文件路径
        file_path, _ = QFileDialog.getSaveFileName(self, "导出数据", "", "CSV Files (*.csv)")
        if file_path:
            # 打开 CSV 文件，使用逗号分隔符
            with open(file_path, 'w', newline='', encoding='utf-8', errors='ignore') as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                # 写入表头
                headers = [self.result_table.horizontalHeaderItem(col).text() for col in
                           range(self.result_table.columnCount())]
                writer.writerow(headers)
                # 写入数据
                for page in self.shodan_current_data:
                    for row in page:
                        ip_str = row['ip_str'] if row.get('ip_str') else ''
                        port_str = row['port'] if row.get('port') else ''
                        domain_str = row['domains'] if row.get('domains') else ''
                        if domain_str: domain_str = ','.join(domain_str)
                        os_str = row['os'] if row.get('os') else ''
                        country_name_str = row['location']['country_name'] if row['location']['country_name'] else ''
                        country_code = row['location']['country_code'] if row['location'][
                            'country_code'] else ''
                        org_str = row['org'] if row.get('org') else ''
                        isp_str = row['isp'] if row.get('isp') else ''
                        hostnames = row['hostnames'] if row.get('hostnames') else ''
                        if hostnames: hostnames = ','.join(hostnames)
                        protocol = row['_shodan']['module'] if row.get('_shodan') else 'unknow'

                        last_update_date = row.get('timestamp')
                        try:
                            probe_date = datetime.strptime(last_update_date, "%Y-%m-%dT%H:%M:%S.%f")
                            last_update_date = probe_date.strftime("%Y-%m-%d %H:%M:%S")
                        except:
                            pass

                        try:
                            title = row['http']['title']
                        except:
                            title = ''
                        try:
                            product = row['product']
                        except:
                            product = ''
                        try:
                            components = row['http']['components']
                            components = '\n'.join(
                                key + ':' + ';'.join(components[key]['categories']) for key in components)
                        except:
                            components = ''

                        try:
                            vulns = row['vulns']
                            vulns = '\n'.join(
                                key + ':' + 'verified' if vulns[key]['verified'] else key + ':' + 'NoTest' for key in
                                vulns)
                        except:
                            vulns = ''

                        row_data = [
                            ip_str,
                            port_str,
                            protocol,
                            product,
                            title,
                            components,
                            vulns,
                            domain_str,
                            hostnames,
                            org_str,
                            os_str,
                            country_name_str,
                            country_code,
                            isp_str,
                            last_update_date
                        ]
                        try:
                            writer.writerow(row_data)
                        except:
                            traceback.print_exc()
                self.log_display.append("结果导出成功")

    def clear_result_table(self):
        # 清空表格内容
        self.result_table.clearContents()
        self.result_table.setRowCount(0)  # 清空行数
        del self.shodan_current_data
        del self.total_page
        self.total_page = []
        self.shodan_current_data = []
        self.search_thread = None
        self.shodan_current_query = ''
        self.current_page_num = 0
        self.total_page = 0

    def clear_log_display(self):
        # 清空日志显示框内容
        self.log_display.setPlainText('')


class ZoomeyePage(QWidget):
    def __init__(self):
        super().__init__()
        self.button_style = button_style + "height: 40px;width: 100px;"

        self.init_ui()
        self.set_style()
        self.Button_binding_event()

    def init_ui(self):
        # 创建布局
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 20, 0, 0)  # 设置左边，顶部，右边，底部间距

        # 第一行：fofa语法输入框、资产类型下拉列表和查询按钮
        fofa_layout = QHBoxLayout()
        fofa_label = QLabel("Zoomeye语法: ")
        self.shodan_input = QLineEdit()

        self.find_button = QPushButton("查询")

        fofa_layout.addWidget(fofa_label)
        fofa_layout.addWidget(self.shodan_input)
        fofa_layout.addWidget(self.find_button)

        # 第二行：清空结果、清空日志、导出结果按钮以及搜索结果信息和页码输入框
        button_result_layout = QHBoxLayout()

        # 创建 QLabel、QComboBox 和 QPushButton 实例
        type_label = QLabel("设备类型：")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["主机设备"])
        self.export_button = QPushButton("导出结果")
        self.clear_result_button = QPushButton("清空结果")
        self.clear_log_button = QPushButton("清空日志")

        # 添加部件到布局中
        button_result_layout.addWidget(type_label,
                                       0)  # 拉伸因子设为 0，意味着这个部件不会随着布局的改变而拉伸。而将下拉框的拉伸因子设为 1，使得它能够在布局中拉伸以填充剩余的空间。
        button_result_layout.addWidget(self.type_combo, 1)  # 指定 self.type_combo 的拉伸因子为 1
        button_result_layout.addStretch(1)  # 添加一个弹簧，使得后面的部件靠右对齐
        button_result_layout.addWidget(self.export_button)
        button_result_layout.addWidget(self.clear_result_button)
        button_result_layout.addWidget(self.clear_log_button)

        # 第三行：表格展示和日志显示
        table_log_layout = QHBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)

        self.result_table.setHorizontalHeaderLabels(["Host", "IP", "Port", "Title"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 列自动调整以填充整个可用的水平空间
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置双击表格时不能编辑
        self.log_display = QTextEdit()
        self.log_display.setSizePolicy(QSizePolicy.Fixed,
                                       QSizePolicy.Expanding)  # QSizePolicy.Fixed 表示部件的大小不会随着布局的变化而改变；而 QSizePolicy.Expanding 表示部件可以在布局中沿着给定的方向（这里是垂直方向）扩展以利用额外的可用空间。

        table_log_layout.addWidget(self.result_table)
        table_log_layout.addWidget(self.log_display)

        # 搜索结果
        result_number_layout = QHBoxLayout()
        self.result_info_label = QLabel("搜索结果共0条,共0页")
        page_label = QLabel("页码：")
        self.page_input = QLineEdit()

        result_number_layout.addWidget(self.result_info_label)
        result_number_layout.addWidget(page_label)
        result_number_layout.addWidget(self.page_input)

        # 调整页码输入框的位置
        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)
        result_number_layout.addItem(spacer)

        # 添加所有行到主布局中
        layout.addLayout(fofa_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(button_result_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(table_log_layout)
        layout.addLayout(result_number_layout)

        self.setLayout(layout)

    def set_style(self):
        self.button_style = button_style + "height: 40px; width: 130px;"

        # 第一行：语法输入框、请求方式下拉列表和查询按钮
        self.find_button.setStyleSheet(self.button_style)
        self.shodan_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.type_combo.setStyleSheet("""
            QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
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
        """)
        # 第二行：清空结果、清空日志、导出数据按钮以及搜索结果信息和页码输入框
        self.clear_result_button.setStyleSheet(self.button_style)
        self.clear_log_button.setStyleSheet(self.button_style)
        self.export_button.setStyleSheet(self.button_style)

        # 最后的搜索结果统计
        self.page_input.setFixedWidth(100)  # 固定输入框宽度
        self.page_input.setStyleSheet(
            """
            border-radius: 13px;
            height: 30px;
            border: 1px solid gray;
            """
        )

    def Button_binding_event(self):
        # 绑定查询按钮点击事件
        self.find_button.clicked.connect(self.insert_data_to_table)
        self.export_button.clicked.connect(self.export_data)
        self.clear_result_button.clicked.connect(self.clear_result_table)
        self.clear_log_button.clicked.connect(self.clear_log_display)

    def insert_data_to_table(self):
        # 获取下拉列表的值
        num_select_value = self.type_combo.currentText()

        # 获取输入框的文本值
        shodan_syntax_text = self.shodan_input.text()

        # 在这里可以使用获取到的值进行查询操作或者其他操作
        print("请求方式的值:", num_select_value)
        print("语法输入框的值:", shodan_syntax_text)

        # 模拟查询结果
        total_results = 100  # 搜索结果总数
        total_pages = 10  # 总页数

        # 更新 result_info_label 的文本
        self.result_info_label.setText(f"搜索结果{total_results}条，共{total_pages}页")
        # 模拟从文本框获取数据
        data = [
            ["Host1", "192.168.1.1", "8080", "Title1"],
            ["Host2", "192.168.1.2", "8081", "Title2"],
            ["Host3", "192.168.1.3", "8082", "Title3"]
        ]

        # 检查表格的行数是否足够，如果不够，则添加新的行
        current_rows = self.result_table.rowCount()
        required_rows = len(data)
        if current_rows < required_rows:
            self.result_table.setRowCount(required_rows)

        # 将数据插入表格中
        for row, row_data in enumerate(data):
            for col, col_data in enumerate(row_data):
                item = QTableWidgetItem(col_data)
                self.result_table.setItem(row, col, item)

        # 在日志框中添加消息
        self.log_display.append("插入成功")

    def export_data(self):
        # 弹出文件对话框，选择导出文件路径
        file_path, _ = QFileDialog.getSaveFileName(self, "导出数据", "", "CSV Files (*.csv)")
        if file_path:
            # 打开 CSV 文件，使用逗号分隔符
            with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                # 写入表头
                headers = [self.result_table.horizontalHeaderItem(col).text() for col in
                           range(self.result_table.columnCount())]
                writer.writerow(headers)
                # 写入数据
                for row in range(self.result_table.rowCount()):
                    row_data = [self.result_table.item(row, col).text() for col in
                                range(self.result_table.columnCount())]
                    writer.writerow(row_data)
                self.log_display.append("结果导出成功")

    def clear_result_table(self):
        # 清空表格内容
        self.result_table.clearContents()
        self.result_table.setRowCount(0)  # 清空行数

    def clear_log_display(self):
        # 清空日志显示框内容
        self.log_display.setPlainText('')


class CensysPage(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()
        self.set_style()
        self.Button_binding_event()

    def init_ui(self):
        # 创建布局
        layout = QVBoxLayout()
        layout.setContentsMargins(10, 20, 0, 0)  # 设置左边，顶部，右边，底部间距

        # 第一行：语法输入框、请求方式下拉列表和查询按钮
        syntax_layout = QHBoxLayout()
        syntax_label = QLabel("censys语法:")
        self.syntax_input = QLineEdit()

        self.find_button = QPushButton("查询")

        syntax_layout.addWidget(syntax_label)
        syntax_layout.addWidget(self.syntax_input)

        syntax_layout.addWidget(self.find_button)

        # 第二行：导出、清空结果、清空日志按钮、搜索结果和页码信息
        button_result_layout = QHBoxLayout()
        type_label = QLabel("请求方式: ")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["Host", "IP", "Cert"])

        button_layout = QHBoxLayout()
        self.export_button = QPushButton("导出结果")
        self.clear_result_button = QPushButton("清空结果")
        self.clear_log_button = QPushButton("清空日志")

        # 添加部件到布局中
        button_layout.addWidget(type_label, 0)  # 拉伸因子设为 0，意味着这个部件不会随着布局的改变而拉伸。而将下拉框的拉伸因子设为 1，使得它能够在布局中拉伸以填充剩余的空间。
        button_layout.addWidget(self.type_combo, 1)  # 指定 self.type_combo 的拉伸因子为 1
        button_layout.addStretch(1)  # 添加一个弹簧，使得后面的部件靠右对齐
        button_layout.addWidget(self.export_button)
        button_layout.addWidget(self.clear_result_button)
        button_layout.addWidget(self.clear_log_button)

        # 将按钮布局和搜索结果布局添加到同一水平布局中
        button_result_layout.addLayout(button_layout)

        # 第四行：表格和日志显示
        table_log_layout = QHBoxLayout()
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(4)
        self.result_table.setHorizontalHeaderLabels(["Column1", "Column2", "Column3", "Column4"])
        self.result_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)  # 列自动调整以填充整个可用的水平空间
        self.result_table.setEditTriggers(QAbstractItemView.NoEditTriggers)  # 设置双击表格时不能编辑
        self.log_display = QTextEdit()
        self.log_display.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)

        table_log_layout.addWidget(self.result_table)
        table_log_layout.addWidget(self.log_display)

        # 搜索结果和页码信息布局
        result_layout = QHBoxLayout()
        self.result_label = QLabel("搜索结果共0条，页码：")
        self.page_input = QLineEdit()

        result_layout.addWidget(self.result_label)
        result_layout.addWidget(self.page_input)

        # 调整页码输入框的位置
        spacer = QSpacerItem(40, 20, QSizePolicy.Expanding, QSizePolicy.Minimum)  # 创建一个可伸缩的空间
        result_layout.addItem(spacer)  # 添加空间以推动页码输入框靠右
        result_layout.addLayout(result_layout)

        # 添加所有行到主布局中
        layout.addLayout(syntax_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(button_result_layout)
        layout.addSpacing(20)  # 添加20px的间隔
        layout.addLayout(table_log_layout)
        layout.addLayout(result_layout)

        self.setLayout(layout)

    def set_style(self):
        self.button_style = button_style + "height: 40px; width: 130px;"

        # 第一行：语法输入框、请求方式下拉列表和查询按钮
        self.find_button.setStyleSheet(self.button_style)
        self.syntax_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.type_combo.setStyleSheet("""
            QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
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
        """)
        # 第二行：导出、清空结果、清空日志按钮、搜索结果和页码信息
        self.export_button.setStyleSheet(self.button_style)
        self.clear_result_button.setStyleSheet(self.button_style)
        self.clear_log_button.setStyleSheet(self.button_style)

        self.page_input.setFixedWidth(100)  # 固定输入框宽度
        self.page_input.setStyleSheet(
            """
            border-radius: 13px;
            height: 30px;
            width: 150px;
            border: 1px solid gray;
            """
        )

    def Button_binding_event(self):
        # 绑定查询按钮点击事件
        self.find_button.clicked.connect(self.insert_data_to_table)
        self.export_button.clicked.connect(self.export_data)
        self.clear_result_button.clicked.connect(self.clear_result_table)
        self.clear_log_button.clicked.connect(self.clear_log_display)

    def insert_data_to_table(self):
        # 获取下拉列表的值
        num_select_value = self.type_combo.currentText()

        # 获取输入框的文本值
        shodan_syntax_text = self.syntax_input.text()

        # 在这里可以使用获取到的值进行查询操作或者其他操作
        print("请求方式的值:", num_select_value)
        print("语法输入框的值:", shodan_syntax_text)

        # 模拟查询结果
        total_results = 100  # 搜索结果总数
        total_pages = 10  # 总页数

        # 更新 result_info_label 的文本
        self.result_label.setText(f"搜索结果{total_results}条，共{total_pages}页")
        # 模拟从文本框获取数据
        data = [
            ["Host1", "192.168.1.1", "8080", "Title1"],
            ["Host2", "192.168.1.2", "8081", "Title2"],
            ["Host3", "192.168.1.3", "8082", "Title3"]
        ]

        # 检查表格的行数是否足够，如果不够，则添加新的行
        current_rows = self.result_table.rowCount()
        required_rows = len(data)
        if current_rows < required_rows:
            self.result_table.setRowCount(required_rows)

        # 将数据插入表格中
        for row, row_data in enumerate(data):
            for col, col_data in enumerate(row_data):
                item = QTableWidgetItem(col_data)
                self.result_table.setItem(row, col, item)

        # 在日志框中添加消息
        self.log_display.append("插入成功")
        # self.log_display.setText("插入成功")  #替换

    def export_data(self):
        # 弹出文件对话框，选择导出文件路径
        file_path, _ = QFileDialog.getSaveFileName(self, "导出数据", "", "CSV Files (*.csv)")
        if file_path:
            # 打开 CSV 文件，使用逗号分隔符
            with open(file_path, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.writer(csv_file, delimiter=',')
                # 写入表头
                headers = [self.result_table.horizontalHeaderItem(col).text() for col in
                           range(self.result_table.columnCount())]
                writer.writerow(headers)
                # 写入数据
                for row in range(self.result_table.rowCount()):
                    row_data = [self.result_table.item(row, col).text() for col in
                                range(self.result_table.columnCount())]
                    writer.writerow(row_data)
                self.log_display.append("结果导出成功")

    def clear_result_table(self):
        # 清空表格内容
        self.result_table.clearContents()
        self.result_table.setRowCount(0)  # 清空行数

    def clear_log_display(self):
        # 清空日志显示框内容
        self.log_display.setPlainText('')


class ConfigPage(QWidget):
    def __init__(self):
        super().__init__()

        self.init_ui()
        self.set_style()
        self.set_conn()

    def set_style(self):
        self.button_style = button_style + "height: 40px; width: 130px;"
        self.save_button.setStyleSheet(self.button_style)
        self.reload_config_button.setStyleSheet(self.button_style)
        self.fofa_email_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.fofa_api_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.shodan_api_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.zoomeye_api_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.censys_uid_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.censys_secret_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.proxy_ip_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.proxy_port_input.setStyleSheet("border-radius: 13px;height: 35px; border: 1px solid gray;")
        self.protocol_combobox.setStyleSheet("""
            QComboBox {
                    border: 1px solid gray;
                    border-radius: 10px;
                    padding: 1px 10px 1px 1px;
                    min-width: 6em;
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
        """)

    def init_ui(self):
        layout = QHBoxLayout()  # 创建左右布局，QHBoxLayout 表示左右布局
        layout.setContentsMargins(10, 20, 0, 0)  # 设置该页面整体的左边距，上边距，右边距，底部边距
        # ----------------------------------------------------------------------开始设置左侧布局
        left_layout = QVBoxLayout()  # 设置左侧界面整体使用上下布局 ; QVBoxLayout表示：上下布局
        # =======创建FOFA配置框
        # # 创建FOFA配置框
        fofa_group = QGroupBox("Fofa配置")
        # fofa_group = QGroupBox()
        # fofa_group.setTitle('FOFA')
        # # 设置标题样式
        # fofa_group.setStyleSheet("QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 3px; }")

        fofa_layout = QHBoxLayout()  # 创建一个左右布局

        # 创建左侧布局用于放置邮箱输入框和API输入框
        fofa_left_layout = QHBoxLayout()

        # 创建水平布局用于放置Email标签和输入框
        fofa_email_layout = QHBoxLayout()
        fofa_email_label = QLabel("Email:")
        self.fofa_email_input = QLineEdit()
        fofa_email_layout.addWidget(fofa_email_label)
        fofa_email_layout.addWidget(self.fofa_email_input)

        # 创建水平布局用于放置API标签和输入框
        fofa_api_layout = QHBoxLayout()
        fofa_api_label = QLabel("API:")
        self.fofa_api_input = QLineEdit()
        fofa_api_layout.addWidget(fofa_api_label)
        fofa_api_layout.addWidget(self.fofa_api_input)

        # 将两个水平布局添加到垂直布局中
        fofa_left_layout.addLayout(fofa_email_layout)
        fofa_left_layout.addLayout(fofa_api_layout)

        # 创建右侧布局用于放置修改按钮
        fofa_right_layout = QVBoxLayout()
        # fofa_modify_button = QPushButton("修改")
        # fofa_modify_button.setObjectName("fofa")
        # fofa_modify_button.clicked.connect(self.save_config)

        # 将修改按钮添加到右侧布局中
        # fofa_right_layout.addWidget(fofa_modify_button)

        # 将左侧布局和右侧布局添加到FOFA配置框中
        fofa_layout.addLayout(fofa_left_layout)
        fofa_layout.addLayout(fofa_right_layout)

        # 将FOFA配置框添加到主布局中
        fofa_group.setLayout(fofa_layout)
        left_layout.addWidget(fofa_group)

        # =========================================创建Shodan配置框
        shodan_group = QGroupBox("Shodan配置")
        shodan_layout = QHBoxLayout()  # 左右布局QHBoxLayout  上下布局：QVBoxLayout
        shodan_api_label = QLabel("API:")
        self.shodan_api_input = QLineEdit()

        shodan_layout.addWidget(shodan_api_label)
        shodan_layout.addWidget(self.shodan_api_input)

        shodan_group.setLayout(shodan_layout)
        left_layout.addWidget(shodan_group)

        # 创建ZoomEye配置框
        zoomeye_group = QGroupBox("ZoomEye配置")
        zoomeye_layout = QHBoxLayout()
        zoomeye_id_label = QLabel("API:")
        self.zoomeye_api_input = QLineEdit()

        zoomeye_layout.addWidget(zoomeye_id_label)
        zoomeye_layout.addWidget(self.zoomeye_api_input)

        zoomeye_group.setLayout(zoomeye_layout)
        left_layout.addWidget(zoomeye_group)

        # =========================================创建Censys配置框
        censys_group = QGroupBox("Censys配置")
        censys_layout = QHBoxLayout()
        censys_uid_label = QLabel("uid:")
        self.censys_uid_input = QLineEdit()
        censys_secret_label = QLabel("secret:")
        self.censys_secret_input = QLineEdit()

        censys_layout.addWidget(censys_uid_label)
        censys_layout.addWidget(self.censys_uid_input)

        censys_layout.addWidget(censys_secret_label)
        censys_layout.addWidget(self.censys_secret_input)

        censys_group.setLayout(censys_layout)
        left_layout.addWidget(censys_group)

        # =========================================创建代理配置
        proxy_group = QGroupBox("代理配置")
        proxy_layout = QVBoxLayout()

        set_proxy_layout = QHBoxLayout()
        proxy_info_layout = QHBoxLayout()

        self.is_shodan_use_proxy_checkbox = QCheckBox("shodan是否使用代理")
        self.is_fofa_use_proxy_checkbox = QCheckBox("fofa是否使用代理")
        set_proxy_layout.addWidget(self.is_shodan_use_proxy_checkbox)
        set_proxy_layout.addWidget(self.is_fofa_use_proxy_checkbox)

        protocol_label = QLabel("协议:")
        self.protocol_combobox = QComboBox()
        self.protocol_combobox.addItems(["http", "socks5"])
        # 创建IP地址输入框部分
        ip_label = QLabel("IP地址:")
        self.proxy_ip_input = QLineEdit()
        # 创建端口输入框部分
        port_label = QLabel("端口:")
        self.proxy_port_input = QLineEdit()

        proxy_info_layout.addWidget(protocol_label)
        proxy_info_layout.addWidget(self.protocol_combobox)
        proxy_info_layout.addWidget(ip_label)
        proxy_info_layout.addWidget(self.proxy_ip_input)
        proxy_info_layout.addWidget(port_label)
        proxy_info_layout.addWidget(self.proxy_port_input)

        proxy_layout.addLayout(set_proxy_layout)
        proxy_layout.addLayout(proxy_info_layout)

        # 将proxy_layout
        proxy_group.setLayout(proxy_layout)
        # 将新配置框添加到左侧布局中
        left_layout.addWidget(proxy_group)

        # ----------------------------------------------------------------------------创建右侧布局
        right_layout = QVBoxLayout()

        # 创建配置说明框
        config_info_group = QGroupBox("配置说明")
        config_info_layout = QVBoxLayout()
        config_info_label = QLabel(
            '''首次启动，需要先配置\n要使用的搜索引擎的api\n信息然后点击“保存”\n再点击“重新加载”即可。''')
        config_info_layout.addWidget(config_info_label)
        config_info_group.setLayout(config_info_layout)

        # 添加配置说明框和保存按钮到右侧布局
        right_layout.addWidget(config_info_group)
        self.reload_config_button = QPushButton("重新加载")
        right_layout.addWidget(self.reload_config_button)
        self.save_button = QPushButton("保存")
        right_layout.addWidget(self.save_button)

        # 将左右布局添加到主布局中
        layout.addLayout(left_layout)
        layout.addLayout(right_layout)

        self.setLayout(layout)

    def set_conn(self):
        self.save_button.clicked.connect(self.save_config)  # 连接保存所有配置的槽函数

        def slot_reload_config():
            g_signal.s_reload_config.emit(True)

        self.reload_config_button.clicked.connect(slot_reload_config)

    def save_config(self):
        choice = QMessageBox.question(
            self,
            '确认',
            '是否保存？')

        if choice == QMessageBox.Yes:
            config = ConfigObj()
            config.filename = 'config.ini'

            # fofa
            config['fofa_email'] = {}
            config['fofa_email']['your_email'] = self.fofa_email_input.text()

            config['fofa_key'] = {}
            config['fofa_key']['fofa_key'] = self.fofa_api_input.text()

            # shodan
            config['shodan_api'] = {}
            config['shodan_api']['your_api'] = self.shodan_api_input.text()

            # zoomeye
            config['zoomeye_api'] = {}
            config['zoomeye_api']['your_zoomeye_api'] = self.zoomeye_api_input.text()

            # censys
            config['censys_uid'] = {}
            config['censys_uid']['censys_uid'] = self.censys_uid_input.text()
            config['censys_secret'] = {}
            config['censys_secret']['censys_secret'] = self.censys_secret_input.text()

            config['global'] = {
                'is_shodan_use_proxy': '1' if self.is_shodan_use_proxy_checkbox.isChecked() else '0',
                'is_fofa_use_proxy': '1' if self.is_fofa_use_proxy_checkbox.isChecked() else '0',
                'proxy_type': self.protocol_combobox.currentText(),
                'proxy_server_ip': self.proxy_ip_input.text(),
                'proxy_port': self.proxy_port_input.text(),
            }
            # print(config)
            config.write()

            QMessageBox.information(self, "保存成功",
                                    "如果你修改了代理配置并希望立刻应用到shodan查询，需要重启程序，其他的修改可以保存后点击\"重新加载\"即可")
            # if confirmation == QMessageBox.Yes:
            #     QApplication.quit()  # 关闭当前程序
            #     subprocess.Popen([sys.executable] + sys.argv)  # 启动新的程序实例


class MainWindow(QMainWindow):
    s_reload_config = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("百川 · 被动信息融合工具")
        self.setGeometry(600, 300, 1500, 1000)  # 800, 400 是窗口左上角在屏幕上的 x 和 y 坐标。100 是窗口的宽度。600 是窗口的高度。

        font = QFont("Microsoft YaHei", 14)  # 字体和大小
        QApplication.setFont(font)

        icon = QIcon("icon/main.png")
        self.setWindowIcon(icon)

        self.create_widgets()
        self.create_layout()
        self.set_icon()
        self.set_conn()
        self.config_init()

    def config_init(self):
        try:
            global cf
            cf = ConfigParser()
            cf.read('config.ini')
            #
            # 1.读取 代理配置
            global config_dic
            proxy_server_ip = cf.get('global', 'proxy_server_ip') if cf.get('global', 'proxy_server_ip') != '""' else ''
            proxy_port = cf.get('global', 'proxy_port') if cf.get('global', 'proxy_port') != '""' else ''
            proxy_type = cf.get('global', 'proxy_type') if cf.get('global', 'proxy_type') != '""' else ''

            config_dic['proxy_server_ip'] = proxy_server_ip
            config_dic['proxy_port'] = proxy_port
            config_dic['proxy_type'] = proxy_type
            config_dic['is_fofa_use_proxy'] = cf.get('global', 'is_fofa_use_proxy') if cf.get('global',
                                                                                              'is_fofa_use_proxy') != '""' else ''
            config_dic['is_shodan_use_proxy'] = cf.get('global', 'is_shodan_use_proxy') if cf.get('global',
                                                                                                  'is_shodan_use_proxy') != '""' else ''

            if (config_dic['is_shodan_use_proxy'] == '1' or config_dic[
                'is_fofa_use_proxy'] == '1') and proxy_type and proxy_server_ip and proxy_port and proxy_type:
                global g_proxies
                g_proxies = {
                    'http': f'{proxy_type}://{proxy_server_ip}:{proxy_port}',
                    'https': f'{proxy_type}://{proxy_server_ip}:{proxy_port}',
                }
            else:
                g_proxies = {}
            config_dic['proxies'] = g_proxies
            # 2.读取fofa配置
            config_dic['fofa'] = {}

            config_dic['fofa']['fofa_key'] = cf.get('fofa_key', 'fofa_key') if cf.get('fofa_key',
                                                                                      'fofa_key') != '""' else ''
            config_dic['fofa']['fofa_mail'] = cf.get('fofa_email', 'your_email') if cf.get('fofa_email',
                                                                                           'your_email') != '""' else ''

            # 3.读取shodan配置
            config_dic['shodan'] = {}
            config_dic['shodan']['shodan_api'] = cf.get('shodan_api', 'your_api') if cf.get('shodan_api',
                                                                                            'your_api') != '""' else ''

            # 4.读取zoomeye配置
            config_dic['zoomeye'] = {}
            config_dic['zoomeye']['zoomeye_api'] = cf.get('zoomeye_api', 'your_zoomeye_api') if cf.get('zoomeye_api',
                                                                                                       'your_zoomeye_api') != '""' else ''

            # 5.读取censys配置
            config_dic['censys'] = {}
            config_dic['censys']['censys_uid'] = cf.get('censys_uid', 'censys_uid') if cf.get('censys_uid',
                                                                                              'censys_uid') != '""' else ''
            config_dic['censys']['censys_secret'] = cf.get('censys_secret', 'censys_secret') if cf.get('censys_secret',
                                                                                                       'censys_secret') != '""' else ''

            self.config_page.fofa_api_input.setText(config_dic['fofa']['fofa_key'])
            self.config_page.fofa_email_input.setText(config_dic['fofa']['fofa_mail'])

            self.config_page.shodan_api_input.setText(config_dic['shodan']['shodan_api'])

            self.config_page.zoomeye_api_input.setText(config_dic['zoomeye']['zoomeye_api'])

            self.config_page.censys_uid_input.setText(config_dic['censys']['censys_uid'])
            self.config_page.censys_secret_input.setText(config_dic['censys']['censys_secret'])

            if config_dic['is_shodan_use_proxy'] == '1':
                self.config_page.is_shodan_use_proxy_checkbox.setChecked(True)
            else:
                self.config_page.is_shodan_use_proxy_checkbox.setChecked(False)

            if config_dic['is_fofa_use_proxy'] == '1':
                self.config_page.is_fofa_use_proxy_checkbox.setChecked(True)
            else:
                self.config_page.is_fofa_use_proxy_checkbox.setChecked(False)

            if proxy_type:
                if proxy_type == 'http':
                    self.config_page.protocol_combobox.setCurrentIndex(0)
                elif proxy_type == 'socks5':
                    self.config_page.protocol_combobox.setCurrentIndex(1)
                else:
                    self.config_page.protocol_combobox.setCurrentIndex(0)
            else:
                self.config_page.protocol_combobox.setCurrentIndex(0)

            if proxy_server_ip:
                self.config_page.proxy_ip_input.setText(proxy_server_ip)

            if proxy_port:
                self.config_page.proxy_port_input.setText(proxy_port)

        except:
            traceback.print_exc()
            QMessageBox.warning(self, "警告",
                                " 检测到未配置api信息，请先配置，否则程序无法正常使用 ")

    def create_widgets(self):
        self.function_tabs = QTabWidget()
        self.fofa_page = FofaPage()
        self.shodan_page = ShodanPage()
        self.zoomeye_page = ZoomeyePage()
        self.censys_page = CensysPage()
        self.easy_search_page = EasySearchPage()
        self.all_in_one_page = AllInOnePage()
        self.config_page = ConfigPage()

    def create_layout(self):
        central_widget = QWidget()
        main_layout = QVBoxLayout(central_widget)
        main_layout.addWidget(self.function_tabs)
        self.setCentralWidget(central_widget)

    # 样式设置
    def set_icon(self):

        # 设置窗口背景色
        # self.setStyleSheet("background-color: #f0f0f0;")
        self.function_tabs.setStyleSheet(
            """
            QTabBar::tab {
                background-color: #d3d3d3; /* 未选择时灰色 */
                color: black;
            }

            QTabBar::tab:selected {
                background-color: #ffffff; /* 选择后白色 */
                color: black;
            }
           
            """
        )

        # 添加图标到选项卡
        self.function_tabs.addTab(self.fofa_page, QIcon("icon/fofa.png"), "fofa")
        self.function_tabs.addTab(self.shodan_page, QIcon("icon/shodan.png"), "shodan")
        self.function_tabs.addTab(self.zoomeye_page, QIcon("icon/zoomeye.png"), "Zoomeye")
        self.function_tabs.addTab(self.censys_page, QIcon("icon/C.png"), "Censys")
        self.function_tabs.addTab(self.easy_search_page, QIcon("icon/easysearch.png"), "快捷搜索")
        self.function_tabs.addTab(self.all_in_one_page, QIcon("icon/allinone.png"), "数据融合查询")
        self.function_tabs.addTab(self.config_page, QIcon("icon/confign.png"), "Config")
        self.fofa_page.signal_data_ok.connect(self.all_in_one_page.signal_task_done)
        self.shodan_page.signal_data_ok.connect(self.all_in_one_page.signal_task_done)

    def set_conn(self):
        g_signal.s_reload_config.connect(self.config_init)

    def slot_switch_to_fofa(self):
        self.function_tabs.setCurrentWidget(self.fofa_page)

    def slot_switch_to_shodan(self):
        self.function_tabs.setCurrentWidget(self.shodan_page)


class Signal(QObject):
    s_reload_config = pyqtSignal(bool)


if __name__ == "__main__":
    app = QApplication(sys.argv)
    g_signal = Signal()
    window = MainWindow()
    # apply_stylesheet(app, theme='dark_purple.xml')  # 应用 dark_teal.xml主题样式
    window.setWindowState(window.windowState() | Qt.WindowMaximized)  # 设置窗口为最大化模式，不覆盖任务栏
    window.show()
    sys.exit(app.exec_())
