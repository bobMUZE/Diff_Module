import math
import whois
import requests
import datetime
import ipaddress
import pandas as pd
import urllib.request
import re, os, json, joblib
from tld import get_tld
from googlesearch import search
from urllib.request import urlopen
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from urllib.error import URLError
from collections import OrderedDict
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class Preprocessing:
    def __init__(self, url):
        self.url = url

    def Entropy(self):
        string = self.url.strip()
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
        return entropy

    def PathEntropy(self):
        string = urlparse(self.url).path.strip()
        prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
        entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
        return entropy

    def HostnameLength(self):
        return len(urlparse(self.url).netloc)

    def PathLength(self):
        return len(urlparse(self.url).path)

    def TldLength(self):
        try:
            return len(get_tld(self.url, fail_silently=True))
        except:
            return -1

    def SpecialCharcter(self):
        count = self.url.count("?") + self.url.count("#") + self.url.count(".") + self.url.count("=")
        return count

    def count_http(self):
        return self.url.count("http")

    def count_htts(self):
        return self.url.count("https")

    def count_www(self):
        return self.url.count("www")

    def numDigits(self):
        digits = [i for i in self.url if i.isdigit()]
        return len(digits)

    def letter_count(self):
        letters = 0
        for i in self.url:
            if i.isalpha():
                letters = letters + 1
        return letters

    def no_of_dir(self):
        urldir = urlparse(self.url).path
        return urldir.count('/')

    def UrlLength(self):
        if len(self.url) < 54:
            return 1
        elif 54 <= len(self.url) <= 75:
            return 0
        else:
            return -1

    def HavingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return 1
        except:
            return -1

    def DomainRegistrationLength(self):
        try:
            total_date = self.GetTotalDate()
            if total_date <= 1264:
                return -1
            else:
                return 0
        except whois.parser.PywhoisError:
            return -1
        except UnicodeError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

        # domain 유효 기간 계산

    def GetTotalDate(self):
        try:
            domain = whois.whois(self.url)
            if type(domain.expiration_date) is list:
                expiration_date = domain.expiration_date[0]
            else:
                expiration_date = domain.expiration_date

            if type(domain.updated_date) is list:
                updated_date = domain.updated_date[0]
            else:
                updated_date = domain.updated_date

            total_date = (expiration_date - updated_date).days
            return total_date
        except whois.parser.PywhoisError:
            return -1
        except TypeError:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except UnicodeError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

    def google_index(self):
        try:
            site = search(self.url, 5)
            return 1 if site else -1
        except requests.exceptions.ConnectionError:
            return -1
        except requests.exceptions.HTTPError:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except URLError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

    def HavingSymbol(self):
        search_symbol = re.search("@", self.url)
        return -1 if search_symbol else 1

    def PrefixSuffix(self):
        search_suffix = re.search("-", self.url)
        return -1 if search_suffix else 1

    def Redirection(self):
        url_parser = urllib.parse.urlparse(self.url)
        path = url_parser.path
        if "//" in path:
            return -1
        else:
            return 1

    def WebTraffic(self):
        try:
            rank = BeautifulSoup(urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(),
                                 "xml").find("REACH")['RANK']
        except TypeError:
            return -1
        except URLError:
            return -1
        except UnicodeEncodeError:
            return -1
        except UnicodeDecodeError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

        rank = int(rank)
        return 1 if rank < 100000 else 0

    def SubmittingToEmail(self):
        try:
            req = requests.get(self.url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=10).content
            soup = BeautifulSoup(req, "html.parser")
            for form in soup.find_all('form', action=True):
                return -1 if "mailto:" in form['action'] else 1
            return 1
        except requests.exceptions.ConnectionError:
            return -1
        except requests.exceptions.ReadTimeout:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except URLError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

    def Iframe(self):
        try:
            req = requests.get(self.url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=10).content
            soup = BeautifulSoup(req, "html.parser")
            for i_frame in soup.find_all('i_frame', width=True, height=True, frameBorder=True):
                if i_frame['width'] == "0" and i_frame['height'] == "0" and i_frame['frameBorder'] == "0":
                    return -1
                if i_frame['width'] == "0" or i_frame['height'] == "0" or i_frame['frameBorder'] == "0":
                    return 0
            return 1
        except requests.exceptions.ConnectionError:
            return -1
        except requests.exceptions.ReadTimeout:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except URLError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

    def sfh(self):
        try:
            resp = requests.get(self.url, headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=10).content
            soup = BeautifulSoup(resp, 'html.parser')
            for form in soup.find_all('form', action=True):
                if form['action'] == "" or form['action'] == "about:blank":
                    return -1
                elif self.url not in form['action'] and self.url not in form['action']:
                    return 0
                else:
                    return 1
            return 1
        except requests.exceptions.ConnectionError:
            return -1
        except requests.exceptions.ReadTimeout:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except URLError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1

    def Favicon(self):
        try:
            resp = requests.get(self.url, timeout=10, headers={"User-Agent": "Mozilla/5.0"}, verify=False).content
            soup = BeautifulSoup(resp, 'html.parser')
            tld = get_tld(self.url, as_object=True)

            tag_link = soup.findAll("link", rel=re.compile("^shortcut icon$", re.I))
            if not tag_link:
                tag_link = soup.findAll("link", rel=re.compile("^icon$", re.I))
            if not tag_link:
                return 0

            for link in tag_link:
                fav = link.get('href')
                parse_fav = urlparse(fav)

                if parse_fav.hostname == "":
                    return 1
                elif tld.domain in fav:
                    return 1

            return -1
        except requests.exceptions.ReadTimeout:
            return -1
        except requests.exceptions.TooManyRedirects:
            return -1
        except URLError:
            return -1
        except requests.exceptions.InvalidSchema:
            return -1
        except requests.exceptions.ConnectionError:
            return -1

    def shortening_service(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        else:
            return 1

    def MakingData(self):
        data_ = {
            "url": [self.url], "entropy": [self.Entropy()],
            "pathentropy": [self.PathEntropy()], "hostname_length": [self.HostnameLength()],
            "path_length": [self.PathLength()], "tld_length": [self.TldLength()], "count-": [self.PrefixSuffix()],
            "count-@": [self.HavingSymbol()], "special_chacter": [self.SpecialCharcter()],
            "count-http": [self.count_http()], "count-https": [self.count_htts()], "count-www": [self.count_www()],
            "count-digit": [self.numDigits()], "count-letter": [self.letter_count()], "count_dir": [self.no_of_dir()],
            "Iframe": [self.Iframe()], "SubmittingToEmail": [self.SubmittingToEmail()],
            "WebTraffic": [self.WebTraffic()],
            "Redirection": [self.Redirection()], "google_index": [self.google_index()],
            "url_length": [self.UrlLength()],
            "DomainRegistrationLength": [self.DomainRegistrationLength()], "HavingIp": [self.HavingIp()],
            "sfh": [self.sfh()], "short_url_service": [self.shortening_service()], "favicon": [self.Favicon()]}
        data = pd.DataFrame(data_)

        return data

class ML:
    def __init__(self, csv_path, time, url_file, xpath):
        self.time = time
        self.url_file = url_file
        self.xpath = xpath
        self.csv_data = pd.DataFrame(csv_path)
        self.x = self.csv_data[["entropy", "pathentropy", "hostname_length", "path_length", "tld_length",
                                "count-", "count-@", "special_chacter", "count-http", "count-https", "count-www",
                                "count-digit", "count-letter", "count_dir", "Iframe", "SubmittingToEmail",
                                "WebTraffic", "Redirection", "google_index", "url_length", "DomainRegistrationLength",
                                "HavingIp", "sfh", "short_url_service", "favicon"]]

    def Predict_Proba(self):
        prediction = joblib.load("forest_model_request.pkl")
        model_finally = prediction.predict_proba(self.x)
        return model_finally

    def DecisionPrediction(self):
        prediction = joblib.load("forest_model_request.pkl")
        binary_prediction = prediction.predict(self.x)
        return binary_prediction

    def PredictionData(self):
        ex_web = [site for site in self.csv_data["url"]]
        url_state = requests.get(self.url_file).status_code # 2020-12-10 추가
        req_time = requests.get(self.url_file).elapsed # 2020-12-10 추가
        
        predict_list = []
        for value in self.Predict_Proba():
            if value[0] > value[1]:
                predict_list.append("{}%".format(int(value[0] * 100)))
            else:
                predict_list.append("{}%".format(int(value[1] * 100)))

        making_log_data = OrderedDict()
        making_log_data["Timestamp"] = f"{self.time}"
        making_log_data["detection"] = True
        making_log_data["URL"] = f"{self.url_file}"
        making_log_data["status_code"] = f"{str(url_state)}" # 2020-12-10 추가 
        making_log_data["response_time"] = f"{str(req_time)}" # 2020-12-10 추가
        making_log_data["xpath"] = f"{self.xpath}"

        making_log_data["module"] = "ML_PhishingDetected"
        making_log_data["log"] = []

        for i in range(0, len(ex_web)):
            # 실제 하나 당 로그는 이 아래에서
            logdata = {"submodule": 0,
                       "external_url": f"{ex_web[i]}",
                       "result": f'{self.DecisionPrediction()[i]}',
                       "percentage": f"{predict_list[i]}"
                       }
            making_log_data["log"].append(logdata)
        testcol.insert_one(making_log_data) # 몽고 DB 추가 데이터 넣는곳
 
# 몽고DB 
class MongoDbManager:
    def __init__(self):
        self._instance = None
        self.client = pymongo.MongoClient("mongodb://muze_root:this-is-root-passwd@3.13.31.198:27017/")

