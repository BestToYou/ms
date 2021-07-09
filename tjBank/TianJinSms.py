import sys
sys.path.append('/data/qjl/NewBlock/BankCode')
import time
import execjs
import re
from pro_bank.tools.Reques import myrequests
import json
from pro_bank.tools.GetMd5 import gen_md5
from pro_bank.tools.DbTools import CMyDb
from pro_bank.config.config_bank import RAR_PATH
import zipfile
from pro_bank.tools.PdfText import pdf_text
from pro_bank.tools.uploadoss import upload_oss_new
class TianJinSms():
    def __init__(self):
        self.bank_id = 32
        self.source_id = 407
        with open("test.js","r",encoding="utf-8")as f:
            data=f.read()
        jscode=data
        self.ctx=execjs.compile(jscode)
    def get_pagelist(self):
        ctime = str(int(time.time() * 1000))
        raw_post = '{"header":{"service":"financeService\/queryProfolioProduct","method":"query","staticData":false,"options":{"sort":[{"property":"GuestRate","direction":"desc"}]},"_t":"'+ctime+'"},"payload":{"OffSet":"1","PrdType":"","RiskLevel":"5","PrdStatus":"0,1","pageSize":10,"InterestDays":"","PfirstAmt":"","queryRiskLevel":"","PrdEarningsCode":"","PrdTemplate":"","FlagOfTime":"0","version":"4.0.1"}}'

        url = "https://www.bankoftianjin.com/enmbank/channel/http.do"
        kv = {"Content-Length": "805",
              "Content-Type": "text/plain; charset=UTF-8",
              "Host": "www.bankoftianjin.com",
              "Connection": "Keep-Alive",
              "Cookie": "JSESSIONID=9MYbRsti53HOcKsDxnpODmAja8x_sgDYPb3xYVlEig8M4dQ4G955!248337199; BIGipServerpool_newsjyh_8000=2667643147.16415.0000",
              "Cookie2": "$Version=1",
              "Accept-Encoding": "gzip",
              "user-agent": "android", }
        raw_key = "sFdpRjxYT0zhPDDt"
        post_data = self.ctx.call("jiami", raw_post, raw_key)
        sm4_data = post_data.split("")[1]
        sm3_data = post_data.split("")[0]
        # 三段式加密，跳过了sm2（原test中的sm2不可用）
        newss = '{}{}8155d8c56cb2d01cfedec01986290353358c794f94ba82069a02bb8953d97672a7b1189a2f57f96a7cb0492c00ea60602f2043bfcc1acf7b81c2f26a5ec64335b0e94064ce95e2cf56d7f1d76378025583c19d170227d2ec028d54a5636cd55929238e84fce35121f9bba788bdacbfd9'.format(
            sm3_data, sm4_data)
        newss = newss.replace("#10", "#01")  # 缝合怪
        r = myrequests(url, headers=kv, data=newss, method="post")
        if r:
            response = self.ctx.call("jiemi", r.text, raw_key)
            response=json.loads(response)
            result=response["result"]
            for item in result.values():
                for one in item:
                    nbsbm=one["PrdCode"]
                    self.get_page_detail(nbsbm)

    def get_page_detail(self,nbsbm,cpdjbm=""):
        url="https://www.bankoftianjin.com/enmbank/channel/httpDownload.do?fileId=FINANCEINTRODUCTION/20210705/{}.zip".format(nbsbm)
        print(url)
        kv = {"Content-Type": "application/octet-stream"}
        r=myrequests(url,headers=kv)
        if r:
            zip_path=RAR_PATH+nbsbm+".zip"
            with open(zip_path,"wb")as f:
                f.write(r.content)
            duoduo=zipfile.ZipFile(zip_path)
            pdf_content=duoduo.read(nbsbm+".pdf")
            if cpdjbm=="":
                text=pdf_text(pdf_content)
                cpdjbm_list = re.findall("[C|A|Z]\d{7}[\d|A|B|C]\d{5,6}", text)
                if cpdjbm_list:
                    cpdjbm = cpdjbm_list[0]
                else:
                    cpdjbm=""
            lh_id=gen_md5(nbsbm+str(self.bank_id))
            md5=gen_md5(nbsbm+str(self.bank_id)+str(self.source_id))
            cpsms_url=upload_oss_new(pdf_content,self.bank_id,3,gen_md5(nbsbm)+".pdf")
            rlist=["lh_id","md5","bank_id","source_id","nbsbm","cpdjbm","cpsms_url","detail_url"]
            llist=[(lh_id,md5,self.bank_id,self.source_id,nbsbm,cpdjbm,cpsms_url,url)]
            try:
                sql_db.save(rlist,llist,"bank_licai_data")
            except Exception as e:
                print(e)
        else:
            print("未找到产品说明书：",nbsbm)

    def test(self,nbsbm):#没用，及时返回了zip文件地址，没有的ndsbm返回的还是404
        ctime = str(int(time.time() * 1000))
        raw_post = '{"header":{"service":"financeService\/executeMCProfolioDeclare","method":"execute","staticData":false,"options":[],"_t":"'+ctime+'"},"payload":{"PrdCode":"'+nbsbm+'","version":"4.0.1"}}'

        url = "https://www.bankoftianjin.com/enmbank/channel/http.do"
        kv = {"Content-Length": "805",
              "Content-Type": "text/plain; charset=UTF-8",
              "Host": "www.bankoftianjin.com",
              "Connection": "Keep-Alive",
              "Cookie": "JSESSIONID=9MYbRsti53HOcKsDxnpODmAja8x_sgDYPb3xYVlEig8M4dQ4G955!248337199; BIGipServerpool_newsjyh_8000=2667643147.16415.0000",
              "Cookie2": "$Version=1",
              "Accept-Encoding": "gzip",
              "user-agent": "android", }
        raw_key = "sFdpRjxYT0zhPDDt"
        post_data = self.ctx.call("jiami", raw_post, raw_key)
        sm4_data = post_data.split("")[1]
        sm3_data = post_data.split("")[0]
        # 三段式加密，跳过了sm2（原test中的sm2不可用）
        newss = '{}{}8155d8c56cb2d01cfedec01986290353358c794f94ba82069a02bb8953d97672a7b1189a2f57f96a7cb0492c00ea60602f2043bfcc1acf7b81c2f26a5ec64335b0e94064ce95e2cf56d7f1d76378025583c19d170227d2ec028d54a5636cd55929238e84fce35121f9bba788bdacbfd9'.format(
            sm3_data, sm4_data)
        newss = newss.replace("#10", "#01")  # 缝合怪
        r = myrequests(url, headers=kv, data=newss, method="post")
        if r:
            response = self.ctx.call("jiemi", r.text, raw_key)
            print(response)

if __name__ == '__main__':
    sql_select_db=CMyDb(dbname="spider")
    sql_select_db.connect_db()
    sql_db=CMyDb(dbname="spider_test")
    sql_db.connect_db()
    tian_obj=TianJinSms()
    select_sql="select * from bs_zd_spider where bank_id=32"
    select_result=sql_select_db.select_many_data(select_sql)
    # for items in select_result:
    #     nbsbmraw=items[3]
    #     cpdjbmraw=items[2]
    #     tian_obj.get_page_detail(nbsbmraw,cpdjbmraw)
    tian_obj.get_pagelist()

