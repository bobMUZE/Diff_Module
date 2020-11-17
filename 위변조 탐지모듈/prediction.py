import os
import re
import math
import json
import joblib
import warnings
import datetime
import pandas as pd

from collections import OrderedDict
from urllib.parse import urlparse
from tld import get_tld
from tld.exceptions import TldDomainNotFound
from tld.exceptions import TldBadUrl
warnings.simplefilter("ignore", UserWarning)

class Preprocessing:
    def __init__(self, url):
        self.url = url

    def UrlLength(self):
        if len(self.url) < 54:
            return 0
        else:
            return 1

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

    def DomainEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).domain.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1
        except TldBadUrl:
            return -1

    def SubDomainEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).subdomain.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1
        except TldBadUrl:
            return -1

    def TldEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).tld.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            return -1
        except TldBadUrl:
            return -1

    def FldEntropy(self):
        try:
            string = get_tld(self.url, as_object=True).fld.strip()
            prob = [float(string.count(c)) / len(string) for c in dict.fromkeys(list(string))]
            entropy = - sum([(p * math.log(p) / math.log(2.0)) for p in prob])
            return entropy
        except TldDomainNotFound:
            match = re.search(
                '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
                '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
            if match:
                # print match.group()
                return -1
            else:
                # print 'No matching pattern found'
                return 1
        except TldBadUrl:
            return -1

    def HostnameLength(self):
        return len(urlparse(self.url).netloc)

    def PathLength(self):
        return len(urlparse(self.url).path)

    def FdLength(self):
        urlpath = urlparse(self.url).path
        try:
            return len(urlpath.split("/")[1])
        except:
            return 0

    def TldLength(self):
        try:
            return len(get_tld(self.url, fail_silently=True))
        except:
            return -1

    def HavingSymbol(self):
        search_symbol = re.search("@", self.url)
        return -1 if search_symbol else 1

    def PrefixSuffix(self):
        search_suffix = re.search("-", self.url)
        return -1 if search_suffix else 1

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

    def having_ip_address(self):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', self.url)  # Ipv6
        if match:
            # print match.group()
            return -1
        else:
            # print 'No matching pattern found'
            return 1

    def MakingData(self):
        data_ = {
            "url": [self.url], "url_length": [self.UrlLength()], "entropy": [self.Entropy()],
            "pathentropy": [self.PathEntropy()], "domainentropy": [self.DomainEntropy()],
            "tldentropy": [self.TldEntropy()],
            "subdomainentropy": [self.SubDomainEntropy()], "FldEntropy": [self.FldEntropy()],
            "hostname_length": [self.HostnameLength()], "path_length": [self.PathLength()],
            "fd_length": [self.FdLength()], "tld_length": [self.TldLength()], "count-": [self.PrefixSuffix()],
            "count-@": [self.HavingSymbol()], "special_chacter": [self.SpecialCharcter()],
            "count-http": [self.count_http()], "count-https": [self.count_htts()], "count-www": [self.count_www()],
            "count-digit": [self.numDigits()], "count-letter": [self.letter_count()], "count_dir": [self.no_of_dir()],
            "use_of_ip": [self.having_ip_address()]}
        data = pd.DataFrame(data_)

        return data


class ML:
    def __init__(self, csv_path):
        self.csv_data = pd.DataFrame(csv_path)
        self.x = self.csv_data[["url_length", "entropy", "pathentropy", "domainentropy", "tldentropy",
                                 "subdomainentropy", "FldEntropy", "hostname_length", "path_length", "fd_length",
                                 "tld_length", "count-", "count-@",
                                 "special_chacter", "count-http", "count-https", "count-www", "count-digit",
                                 "count-letter", "count_dir", "use_of_ip"]]

    def Predict_Proba(self):
        prediction = joblib.load("forest_model.pkl")
        model_finally = prediction.predict_proba(self.x)
        return model_finally

    def DecisionPrediction(self):
        prediction = joblib.load("forest_model.pkl")
        binary_prediction = prediction.predict(self.x)
        return binary_prediction

    def PredictionData(self):
        ex_web = [site for site in self.csv_data["url"]]

        predict_list = []
        for value in self.Predict_Proba():
            if value[0] > value[1]:
                predict_list.append("{}%".format(int(value[0] * 100)))
            else:
                predict_list.append("{}%".format(int(value[1] * 100)))

        making_log_data = OrderedDict()
        log_path = "log.json"
        f = open(log_path, "r", encoding="utf-8")
        dict_info = json.loads(f.read())
        making_log_data["Timestamp"] = f"{datetime.datetime.now()}"
        making_log_data["URL"] = f"url sample"
        making_log_data["detection"] = True

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
            f.close()
            f = open(log_path, "w", encoding="utf8")
            dict_info.append(making_log_data)
            f.write(json.dumps(dict_info, ensure_ascii=False, indent='\t'))



