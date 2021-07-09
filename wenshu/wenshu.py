import base64
import datetime
import json
import re

import requests
from urllib.parse import quote



import execjs
from Crypto.Cipher import DES3

def login_wenshu():
    session = requests.Session()
    author_url = "https://wenshu.court.gov.cn/tongyiLogin/authorize"
    headers_rs ={
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"
    }
    rs_au = session.post(url=author_url,headers=headers_rs)
    #得到鉴权url
    re_url = rs_au.text

    headers = {
        "Referer": re_url,
    }

    login_url = "https://account.court.gov.cn/api/login"
    data = {
        "username": "11111",
        "password": quote(get_js()),
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36"

    }

    a = session.post(url=login_url, data=data, headers=headers)

    print(a.text)
    print(a.headers)

    # 再一次请求
    au_response = session.get(re_url)
    print(au_response.text)
    print(session.cookies.get_dict())
    req(session.cookies.get_dict()['SESSION'])


def req(s):
    url = 'https://wenshu.court.gov.cn/website/parse/rest.q4w'
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Cookie': 'SESSION={}'.format(s),
        # 'Host': 'wenshu.court.gov.cn',
        'Origin': 'https://wenshu.court.gov.cn',
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.90 Safari/537.36",
        'X-Requested-With': 'XMLHttpRequest'
    }
    data1 = {
        'pageId': '1f6abec3b8b801dd408373df90c69608',
        # 'cprqStart': '2020-08-04',
        # 'cprqEnd': '2021-03-18',
        'sortFields': 's50:desc',
        'ciphertext': '',
        'pageNum': '1',
        'queryCondition': '[{"key":"s41","value":"2021-03-25 TO 2021-03-25"}]',
        'cfg': 'com.lawyee.judge.dc.parse.dto.SearchDataDsoDTO@queryDoc',
        '__RequestVerificationToken': 'LaGbT89y2rywBaINRvqOjnEb',
        'pageSize': 5
        # "swsjStart": "2021-03-23",
        # "swsjEnd": "2021-03-25",
    }
    res = requests.post(url, headers=headers, data=data1, verify=False, timeout=60)
    print(res.text)
    res = res.json()
    print(decrypt(res['result'], res['secretKey']))
    print(res)

def decrypt(data, key):
    """des解密，data，key来自response"""
    try:
        now_date = datetime.datetime.now()
        now_date = datetime.datetime.strftime(now_date, "%Y%m%d")
        iv = str(now_date).encode("utf-8")
        key = key.encode("utf-8")
        des3 = DES3.new(key, DES3.MODE_CBC, iv)
        data = base64.b64decode(data)
        res = des3.decrypt(data)
        data = re.findall("(.*})", res.decode())[0]
        return json.loads(data)
    except Exception as e:
        print("decrypt error:", e)
        return data
def get_js():
    f = open(r"sign.js", 'r', encoding='UTF-8')  ##打开JS文件
    line = f.readline()
    htmlstr = ''
    while line:
        htmlstr = htmlstr + line
        line = f.readline()
    ctx = execjs.compile(htmlstr)
    return ctx.call('getPwd',"")



