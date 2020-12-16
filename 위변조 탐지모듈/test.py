import os
import sys
import re
import time
import difflib
import requests
import hashlib
import base64
import whois # pip install python-whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import socket
import json
from collections import OrderedDict
import pymongo

# phishing
from queue import Queue
from prediction import ML, Preprocessing


# 자바 스크립트 - 전체 text 크롤링
class JSDiff(object):

    def __init__(self, text1, text2, name=None):
        self.filename = name
        textlist = re.split("\n", text1)
        text1 = ''
        for i in range(0, len(textlist)):
            if '//' in textlist[i]:
                textlist[i] = textlist[i].replace('//', '\n//') + '$$$$$$'
            text1 = text1 + textlist[i]
        textlist = re.split("\n", text2)
        text2 = ''
        for i in range(0, len(textlist)):
            if '//' in textlist[i]:
                textlist[i] = textlist[i].replace('//', '\n//') + '$$$$$$'
            text2 = text2 + textlist[i]

        self.text1 = text1.replace(" ", "").replace(';', ';\n').replace('{', '{\n').replace('}', '}\n').replace('$$$$$$', '\n').strip()
        self.text2 = text2.replace(" ", "").replace(';', ';\n').replace('{', '{\n').replace('}', '}\n').replace('$$$$$$', '\n').strip()
        self.fromlines = re.split("\n", self.text1)
        self.fromlines = [n + "\n" for n in self.fromlines]
        self.tolines = re.split("\n", self.text2)
        self.tolines = [n + "\n" for n in self.tolines]

    def getDiffDetails(self, fromdesc='', todesc='', context=False, numlines=5, tabSize=8):

        def expand_tabs(line):
            line = line.replace(' ', '\0')
            line = line.expandtabs(tabSize)
            line = line.replace(' ', '\t')
            return line.replace('\0', ' ')

        self.fromlines = [expand_tabs(line) for line in self.fromlines]
        self.tolines = [expand_tabs(line) for line in self.tolines]

        if context:
            context_lines = numlines
        else:
            context_lines = None

        diffs = difflib._mdiff(self.fromlines, self.tolines, context_lines,
                               linejunk=None, charjunk=difflib.IS_CHARACTER_JUNK)

        diffs_list = list(diffs)
        for i in range(0, len(diffs_list)):
            text_modify = diffs_list[i][1][1].strip("\x00").strip("\x01")
            text_origin = diffs_list[i][0][1].strip("\x00").strip("\x01")
            if '//' in text_origin and '//' in text_modify:
                diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)
        return diffs_list

    def format(self):
        self.diffs = self.getDiffDetails(self.text1, self.text2)

        for diff in self.diffs:
            if diff[2] == True:
                print("%-6s %-80s %-80s" % (diff[2], diff[0], diff[1]))


class FileDiff(object):

    def __init__(self):
        self.CHECK_DIR = ['Image_file']
        self.HASH_DB = sys.path[0] + '/hash_db.txt'  # 해시 파일 저장소 이름
        self.ALARM_LOG = 'log/filecheck.log'  # 로그 알람 파일 저장 위치

    # 파일 해시
    def file_hash(self, file_path):
        import hashlib
        md5obj = hashlib.md5()
        size = 102400
        fp = open(file_path, 'rb')
        while True:
            content = fp.read(size)
            if not content:
                break
            md5obj.update(content)
        fp.close()
        return md5obj.hexdigest()


    # 디렉토리에있는 모든 파일의 해시 값을 얻습니다.
    # [[파일 경로, 해시 값], [파일 경로, 해시 값]]을 포함한 콘텐츠 hash_list_content 반환
    def dir_hash(self, path):
        hash_list_content = []
        for root, dirs, files in os.walk(path, topdown=True):
            for filename in files:
                if os.path.exists(os.path.join(root, filename)):
                    hash_list = []
                    hash_list.append(os.path.join(root, filename))
                    hash_list.append(self.file_hash(os.path.join(root, filename)))
                    hash_list_content.append(hash_list)
        return hash_list_content

    # 저장된 해시 값 파일 가져 오기
    # [[], []]를 포함한 컨텐츠 history_hash_list_content 반환
    def get_history_hash_list(self):
        if not os.path.exists(self.HASH_DB):
            self.write_hash_db("Initialization")
            return "", ""
        if os.path.getsize(self.HASH_DB) == 0:
            self.write_hash_db("Initialization")
            return "", ""
        # 해시 파일의 내용을 데이터 그룹으로 가져옵니다.
        history_hash_list_content = []
        # 배열에 대한 파일 경로의 절대 경로를 가져옵니다
        history_file_path_list = []
        for line in open(self.HASH_DB, encoding='utf-8'):
            if line != "" or line != None:
                tmp_hash = []
                tmp_hash.append(line.split('||')[0].split('\n')[0])
                tmp_hash.append(line.split('||')[1].split('\n')[0])
                history_hash_list_content.append(tmp_hash)
                history_file_path_list.append(line.split('||')[0].split('\n')[0])
        return history_hash_list_content, history_file_path_list

    # 해시 데이터 파일 쓰기
    def write_hash_db(self, type):
        time_string = time.time()
        if type == "Initialization":
            if not os.path.exists(self.HASH_DB):
                f = open(self.HASH_DB, mode='w', encoding='utf-8')
                f.close()
            if os.path.getsize(self.HASH_DB) == 0:
                f = open(self.HASH_DB, mode='a', encoding='utf-8')
                for check_dir in self.CHECK_DIR:
                    for hash_list in self.dir_hash(check_dir):
                        f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(
                            time.strftime('%c', time.localtime(time.time()))).replace(' ', '_').replace(':',
                                                                                                        '_') + "\n")
                f.close()
        if type == "Coverage":
            if os.path.exists(self.HASH_DB):
                f = open(self.HASH_DB, 'w', encoding='utf-8')
                for check_dir in self.CHECK_DIR:
                    for hash_list in self.dir_hash(check_dir):
                        f.write(hash_list[0] + "||" + hash_list[1] + "||" + str(
                            time.strftime('%c', time.localtime(time.time()))).replace(' ', '_').replace(':',
                                                                                                        '_') + "\n")
                f.close()

    # 해당 디렉토리의 해시가 변경되었는지 확인
    def check_dir_hash(self):
        HASH_FILE_TYPE = False
        current_hash_list_content = []

        # 로그 인터페이스 초기화
        logger = self.loging()
        # HASH 목록 가져 오기
        history_hash_list_content, history_file_path_list = self.get_history_hash_list()
        if len(history_hash_list_content) == 0 or len(history_file_path_list) == 0:
            return

        # 모니터링 디렉토리 감지 시작
        for check_dir in self.CHECK_DIR:
            current_hash_list_content = self.dir_hash(check_dir)
            for hash_list in current_hash_list_content:
                if not hash_list in history_hash_list_content:
                    HASH_FILE_TYPE = True
                    if hash_list[0] in history_file_path_list:
                        logger.info("파일 :%s, 작업:Edit, 위험수준:Medium, MD5：%s" % (hash_list[0], hash_list[1]))
                    else:
                        logger.info("파일:%s, 작업:Create, 위험수준:Medium, MD5：%s" % (hash_list[0], hash_list[1]))

        if HASH_FILE_TYPE:
            self.write_hash_db("Coverage")

    # syslog 인쇄를 위해 지정된 파일에 출력을 기록합니다.
    def loging(self):
        import logging
        logging.basicConfig(level=logging.INFO)
        logger = logging.getLogger('FileCheck')
        fh = logging.FileHandler(self.ALARM_LOG)
        fh.setLevel(logging.INFO)
        formatter = logging.Formatter('%(asctime)s - %(message)s')
        fh.setFormatter(formatter)
        logger.addHandler(fh)
        return logger





class HtmlDiff(object):

    def __init__(self, text1, text2, name=None, timestamp=None, xpath=None, responseCode = None, requestTime=None):
        self.text1 = text1.replace("\n", "").replace("<", "\n<").strip()
        self.text2 = text2.replace("\n", "").replace("<", "\n<").strip()
        self.fromlines = re.split("\n", self.text1)
        self.fromlines = [n + "\n" for n in self.fromlines]
        self.tolines = re.split("\n", self.text2)
        self.tolines = [n + "\n" for n in self.tolines]
        self.filename = name
        self.timestamp = timestamp
        self.xpath = xpath
        self.responseCode = responseCode
        self.requestTime = requestTime

    def get_Diff(self, fromdesc='', todesc='', context=False, numlines=5, tabSize=8):

        def expand_tabs(line):
            line = line.replace(' ', '\0')
            line = line.expandtabs(tabSize)
            line = line.replace(' ', '\t')
            return line.replace('\0', ' ')

        self.fromlines = [expand_tabs(line) for line in self.fromlines]
        self.tolines = [expand_tabs(line) for line in self.tolines]

        if context:
            context_lines = numlines
        else:
            context_lines = None

        diffs = difflib._mdiff(self.fromlines, self.tolines, context_lines,
                               linejunk=None, charjunk=difflib.IS_CHARACTER_JUNK)
        diffs_list = list(diffs)
        ifram_temp_bool = False
        jquery_temp_bool = False
        url_temp_bool = False

        for i in range(0, len(diffs_list)):
            text_modify = diffs_list[i][1][1].replace("\x00^",'').replace("\x00+", '').replace("\x00-", '').replace("\x01", '').replace("\n", '')
            text_origin= diffs_list[i][0][1].replace("\x00^",'').replace("\x00+", '').replace("\x00-", '').replace("\x01", '').replace("\n", '')

            if '<iframe' in text_origin and '<iframe' in text_modify:
                ifram_temp_bool = True

            elif '<script src' in text_origin and 'jquery' in text_modify and '<script src' in text_modify:
                jquery_temp_bool = True

            elif 'href' in text_origin and 'href' in text_modify:
                url_temp_bool = True

            if diffs_list[i][2] == True:

                diffs_list[i] = (text_origin, text_modify, True)

                if ifram_temp_bool == True:
                    temp_list0 = text_origin.replace('src =', 'src=').split('src=')
                    temp_list1 = text_modify.replace('src =', 'src=').split('src=')
                    if len(temp_list0) > 1 and len(temp_list1) > 1:
                        temp_list0 = temp_list0[1].split('>')
                        temp_list0 = temp_list0[0].strip().split(' ')
                        original_iframe_link = temp_list0[0].strip('"').strip("'")
                        temp_list1 = temp_list1[1].split('>')
                        temp_list1 = temp_list1[0].strip().split(' ')
                        modify_iframe_link = temp_list1[0].strip('"').strip("'")
                        temp0 = original_iframe_link.replace('http://', '').replace('https://', '')
                        temp1 = modify_iframe_link.replace('http://', '').replace('https://', '')
                        if temp0[0]=='/' or temp0[0]=='#':
                            original_domain = self.filename
                        else:
                            temp_list0 = temp0.split('/')
                            original_domain = temp_list0[0].replace('www.', '')
                        if temp1[0]=='/' or temp1[0]=='#':
                            modify_domain = self.filename
                        else:
                            temp_list1 = temp1.split('/')
                            modify_domain = temp_list1[0].replace('www.', '')

                        temp_url = self.filename.replace('http://','').replace('https://','').split('/')[0]

                        if original_domain == modify_domain or temp_url.split('.')[-2]+"."+temp_url.split('.')[-1] in modify_domain:
                            diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)
                        else:
                            diffs_list[i] = (text_origin, text_modify, 'Iframe 도메인변조')
                            # iframe의 src domain이 같으면 참이라고 생각한다.
                            # modified iframe에 page domain 이 포함되면 참이라고 생각한다.

                if jquery_temp_bool == True:
                    jq = JqueryDiff()
                    if jq.check_integrity(text_modify) == True:
                        diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)
                    else:
                        diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], '위험Jquery사용')

                if url_temp_bool == True:

                    temp_list0 = text_origin.replace('href =', 'href=').split('href=')
                    temp_list1 = text_modify.replace('href =', 'href=').split('href=')

                    try:
                        temp_list0 = temp_list0[1].split('>')
                        temp_list0 = temp_list0[0].strip().split(' ')
                        original_url_link = temp_list0[0].strip('"').strip("'")
                        temp_list1 = temp_list1[1].split('>')
                        temp_list1 = temp_list1[0].strip().split(' ')
                        modify_url_link = temp_list1[0].strip('"').strip("'")

                        temp_url = self.filename.replace('http://', '').replace('https://', '').split('/')[0]
                        internal_domain = temp_url.split('.')[-2]+"."+temp_url.split('.')[-1]

                        # 내부링크 -> 내부링크 변조
                        if (original_url_link[0]=='/'or original_url_link[0]=='#') and (modify_url_link[0]=='/'or modify_url_link[0]=='#'):
                            diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)
                        elif internal_domain in original_url_link and internal_domain in modify_url_link:
                            diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)

                        # 내부링크 -> 외부링크
                        elif internal_domain in original_url_link or original_url_link[0]=='/'or original_url_link[0]=='#':
                            mal_url = Mal_URL()
                            result = mal_url.main(modify_url_link)

                            # self.filename = url
                            # self.timestamp = time
                            # self.xpath = xpath
                            # self.responseCode = responseCode
                            # self.requestTime = requestTime
                            # modify_url_link

                            # 큐에 넣어주시면 됩니다.
                            phishing_q = Queue()
                            phishing_q.put(modify_url_link)
                            phishing_data = phishing_q.get()
                            if phishing_data is None:
                                print("Empty data")
                            else:
                                phishing_search = Preprocessing(phishing_data).MakingData()
                                Machine = ML(phishing_search, time=self.timestamp, url_file=self.filename,
                                             xpath=self.xpath, response_status=self.responseCode,
                                             request_time=self.requestTime).PredictionData()

                            diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], '외부링크타입:'+result)

                        # 외부링크 -> 외부링크
                        else:
                            mal_url = Mal_URL()
                            result = mal_url.main(modify_url_link)

                            # self.filename = url
                            # self.timestamp = time
                            # self.xpath = xpath
                            # self.responseCode = responseCode
                            # self.requestTime = requestTime
                            # modify_url_link

                            # 큐에 넣어주시면 됩니다.
                            phishing_q = Queue()
                            phishing_q.put(modify_url_link)
                            phishing_data = phishing_q.get()
                            if phishing_data is None:
                                print("Empty data")
                            else:
                                phishing_search = Preprocessing(phishing_data).MakingData()
                                Machine = ML(phishing_search, time=self.timestamp, url_file=self.filename,
                                             xpath=self.xpath, response_status=self.responseCode,
                                             request_time=self.requestTime).PredictionData()

                            if result == '정상':
                                diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], False)
                            else:
                                diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], '외부링크타입:' + result)
                    except:
                        diffs_list[i] = (diffs_list[i][0], diffs_list[i][1], True)

            jquery_temp_bool = False
            url_temp_bool = False
            if '</iframe' in text_origin and '</iframe' in text_modify:
                ifram_temp_bool = False

        return diffs_list


    def format(self):
        self.diffs = self.get_Diff(self.text1, self.text2)

        raw_data = []

        for diff in self.diffs:
            if diff[2] == False:
                continue
            elif diff[2] == True:
                rawraw_data = OrderedDict()
                rawraw_data['submodule'] = 1
                rawraw_data['original_code'] = diff[0]
                rawraw_data['modified_code'] = diff[1]
                raw_data.append(rawraw_data)

            elif diff[2] == '위험Jquery사용':
                rawraw_data = OrderedDict()
                rawraw_data['submodule'] = 3
                rawraw_data['malJquery_Detection'] = diff[1]
                raw_data.append(rawraw_data)

            elif diff[2] == 'Iframe 도메인변조':
                rawraw_data = OrderedDict()
                rawraw_data['submodule'] = 4
                rawraw_data['original_code'] = diff[0]
                rawraw_data['modified_code'] = diff[1]
                raw_data.append(rawraw_data)

            elif '외부링크타입:' in str(diff[2]):
                rawraw_data = OrderedDict()
                rawraw_data['submodule'] = 2
                rawraw_data['malURL_Type'] =  diff[2].split(":")[1]
                rawraw_data['malURL_Detection'] = diff[1]
                raw_data.append(rawraw_data)

        return raw_data



class JqueryDiff(object):


    def __init__(self):
        self.jquery_DB_path = 'jquery_DB.csv'
        self.HASHERS = {"sha256": hashlib.sha256, "sha384": hashlib.sha384, "sha512": hashlib.sha512}

    def calculate_hash(self, path: str, algorithm: str) -> str:
        hasher = self.HASHERS[algorithm]
        content = requests.get(path).text
        digest = hasher(content.encode()).digest()
        return base64.b64encode(digest).decode()

    def calculate_integrity(self, path: str, algorithm: str = "sha256") -> str:
        return "-".join([algorithm, self.calculate_hash(path, algorithm)])

    def check_integrity(self, jquery_code):
        src = jquery_code.replace(' ', '').split('src=')[1].split('"')[1]
        pattern = """
        (0|1|2|3) # 버전 0,1,2,3
        \.{0,1}
        \d{1,2} 
        \.{0,1}
        \d{1,2}
        """
        if re.search(pattern, src, re.X) == None:
            return False
        else:
            res = str(re.search(pattern, src, re.X)).split('match=')[1].strip('>')
            is_min = 'X'
            if 'min' in src:
                is_min = 'O'
            f = open('jquery_DB.txt', 'r', encoding='utf8')
            DB = f.readlines()
            is_right_version = False
            for data in DB:
                if res.strip("'") + '||' + is_min + '||' in data:
                    is_right_version = True
                    integrity = data.strip().split('||')[2]
                    if self.calculate_integrity(src) == integrity:
                        return True
                    else:
                        return False
            if is_right_version == False:
                return False


class Mal_URL(object):

    def malware_check(self, my_url, a_key):  # api key 5개 = 1분에 최대 20개 검사가능
        # 확장자 검사
        pattern = ('.m', '.a', '.exe', '.sh', '.zip', '.rar', '.x86', '.arm', '.mpsl', '.mips', '.ppc', '.m68k', '.z')
        pattern2 = ('m', 'a', 'exe', 'sh', 'zip', 'rar', 'x86', 'arm', 'mpsl', 'mips', 'ppc', 'm68k', 'z')
        url = re.sub('[-+,#\?:^$@*\"※~&%ㆍ!』\\‘|\(\)\[\]\<\>`\'…》]', '', my_url).rstrip('/')
        temp_list = url.split('/')
        last = temp_list[-1]
        pre_last = temp_list[-2]
        if last.endswith(pattern) or last in pattern2 or pre_last in pattern2:
            return 1
        # 바이러스 토탈 API 검사
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        while True:
            second = int(time.strftime('%c', time.localtime(time.time())).split(':')[2].split(' ')[0])
            i = second % len(a_key)
            params = {"apikey": a_key[i], "resource": my_url, "scan": 1}
            response = requests.get(url, params=params)
            if response.status_code == 200:
                json = response.json()
                if json['response_code'] == 1:
                    try:
                        if json['positives'] == 0:
                            return 0
                        else:  # 안전하면 0, 악성이면 1 , 홈페이지 이상이면 -1
                            return 1
                    except:
                        return -1
                else:
                    return -1
            else:
                time.sleep(0.5)

    def BadContents_Pishing_check(self, my_url):
        # 유해 컨텐츠 사이트 탐지
        HEADERS = {
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'}
        try:
            sourcecode = requests.get(my_url, headers=HEADERS).text
            count = (sourcecode.count('.gif\"') + sourcecode.count('gif?') - sourcecode.count('.gif?')) ** 2 \
                    + sourcecode.count('보지') * 500 + sourcecode.count('자지') * 500 + sourcecode.count('야동') * 20 \
                    + sourcecode.count('야사') * 30 + sourcecode.count('포르노') * 20 + sourcecode.count('노모') * 500 \
                    + sourcecode.count('여캠') * 30 + sourcecode.count('토토') * 100 + sourcecode.count('토렌트') * 500 \
                    + sourcecode.count('먹튀') * 500 + sourcecode.count('업소후기') * 500 + sourcecode.count(
                '지역별 업소') * 500 + sourcecode.count('업소커뮤니티') * 500

            # 정부에서 알아서 차단되는 사이트 분류하기
            # 작은 뉴스회사와의 차이점 연구하기
            # 변조가 아닌  게시판 글에서의 링크유해성 판단하기

            if count >= 200:
                return 1  # 유해컨텐츠이면 1

            # 피싱 사이트 탐지
            url_info = self.get_whois(my_url).split('_')
            list_href = []
            soup = BeautifulSoup(sourcecode, "html.parser")
            try:
                for href in soup.find_all("a", limit=20):
                    if 'http' in href["href"]:
                        href_info = self.get_whois(href["href"])
                        href_list = href_info.split('_')
                        if href_list[0] + href_list[1] != url_info[0] + url_info[1]:
                            list_href.append(href_info)
                count_dic = {}
                for i in list_href:
                    try:
                        count_dic[i] += 1
                    except:
                        count_dic[i] = 1
                count_dic = sorted(count_dic.items(), reverse=True, key=lambda item: item[1])
                if count_dic[0][1] > 5:
                    return 2
                else:
                    return 0
            except:
                return 0
        except:
            # Mozilla 또는 파이썬 라이브러리에서 자체 차단
            return 1

    def get_whois(self, url):
        try:
            w = whois.whois(url)
        except whois.parser.PywhoisError:  # NOT FOUND
            return "ERROR"
        # ip 주소 알아내기
        o = urlparse(url)
        hostname = o.hostname
        port = o.port
        ip_addr = socket.getaddrinfo(hostname, port)[0][4][0][0:-3].rstrip(".")
        return str(w.zipcode) + "_" + str(w.country) + "_" + str(ip_addr)

    def main(self, url):
        api_key = ["a2c4c89637e57dc27bdb3048989da16c530c2dfffc4783c62fa95ea936e19d80"]
        if self.malware_check(url, api_key) == 1:
            return 'Mal'
        else:
            x = self.BadContents_Pishing_check(url)
            if x == 1:
                return 'Bad'
            elif x == 2:
                return 'Phishing'
            else:
                return 'Normal'



class MongoDbManager:
    def __init__(self):
        self._instance = None
        self.client = pymongo.MongoClient("mongodb://muze_root:this-is-root-passwd@3.13.31.198:27017/")


def diff_html(semiCrawling_path, page_url, time, xpath, responseCode, requestTime):

    # 파라미터
    # test1 = (원본값)
    # test2 = 세미크롤링에서 가져온 값 (변조값)
    # page_url
    # timestamp
    # xpath

    f = open('1.html', "r", encoding="utf8")
    text1 = f.read()
    f.close()
    f = open(semiCrawling_path, "r", encoding="utf8")
    text2 = f.read()
    f.close()

    log_data = OrderedDict()
    log_data['time'] = time
    log_data['detection'] = False
    log_data['url'] = page_url
    log_data['status_code'] = responseCode
    log_data['request_time'] = requestTime
    log_data['xpath'] = xpath
    log_data['progress'] = -1
    log_data['module'] = 'HTML'

    dbManager = MongoDbManager()
    testcol = dbManager.client['muzeDB']['logCollection']


    if text1.replace("\n", "").replace(" ", "") == text2.replace("\n", "").replace(" ", ""):
        testcol.insert_one(log_data)
        return True
    else:
        htmlDiff = HtmlDiff(text1, text2, name=page_url, timestamp=time, xpath= xpath, responseCode = responseCode, requestTime=requestTime)
        log_data['logdata']=htmlDiff.format()
        log_data['detection'] = True
        testcol.insert_one(log_data)
        return False

# submodule=1 : HTML 소스코드 위변조탐지
# submodule=2 : URL 안전성검사
# submodule=3 : 위험 Jquery 사용탐지
# submodule=4 : Iframe 도메인 변경탐지



diff_html('3.html', 'http://3.131.17.188/wordpress:8080', 1608125301.3266618, "//*[@id=\"NM_NEWSSTAND_HEADER\"]", 200, 0.624045)
