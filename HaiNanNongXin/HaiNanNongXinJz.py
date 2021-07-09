import requests
import ssl
from pro_bank.tools.GetMd5 import gen_md5
from pro_bank.tools.Reques import myrequests
class HaiNanNongXinJz():

    def get_jz(self,nbsbm="TTF2020001",page_index=0):#page_index从0开始，一次增20
        page_index=str(page_index)
        url="https://netbank.hainanbank.com.cn:5060/personal/JsonTransServlet?_locale=zh_CN&_local=zh_CN&_CCNativeReq=Y&channelNo=10&clientToken=&mobileType=0&sysVersion=3.3.1&hardwareData=867982073900020;867982073900020;e67ca099b895ef51&userId=&mobpayType=0&mac=ca:21:13:bc:cf:85&isRoot=0&mobileModel=XiaoMi"
        kv={"Accept-Encoding":"identity",
        # "Cookie":"route=a31291107164532e5bd37dd0e620d13c",
        "Accept-Language":"zh-CN,zh;q=0.8",
        "Connection":"close",
        # "Cookie":"route=a31291107164532e5bd37dd0e620d13c",
        # "Cookie":"route=a31291107164532e5bd37dd0e620d13c",
        "Content-Type":"application/x-www-form-urlencoded;charset=UTF-8",
        "Content-Length":"127",
        "User-Agent":"Dalvik/2.1.0 (Linux; U; Android 8.1.0; XiaoMi/OPM1.171019.011)",
        "Host":"netbank.hainanbank.com.cn:5060"}
        signature=gen_md5("1{}{}20d79d94e665b55a3b1a2d45b9cf8e7c61".format(page_index,nbsbm))
        print(signature)
        post_data="indexId={}&showCount=20&acct_no=&prod_code={}&clientType=1&transCode=P222039&Signature={}".format(page_index,nbsbm,signature)
        #r=requests.post(url,headers=kv,data=post_data,cert="client_keystore.pem")
        r=myrequests(url,headers=kv,data=post_data,cert="client_keystore.pem",method="post")
        if r:
            print(r.text)

    def get_page(self):
        url = "https://netbank.hainanbank.com.cn:5060/personal/JsonTransServlet?_locale=zh_CN&_local=zh_CN&_CCNativeReq=Y&channelNo=10&clientToken=&mobileType=0&sysVersion=3.3.3&hardwareData=347530908711345&userId=&mobpayType=0&mac=20%3A5e%3A36%3A86%3A57%3A36&isRoot=1&mobileModel=XiaoMi"
        kv = {
            "Accept-Encoding": "identity",
            "Cookie": "route=4ee4544a7dea549c3577ca3c4959c13d",
            "Accept-Language": "zh-CN,zh;q=0.8",
            "Connection": "close",
            "Content-Type": "application/x-www-form-urlencoded;charset=UTF-8",
            "Content-Length": "269",
            "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 8.1.0;OPM1.171019.011)",
            "Host": "netbank.hainanbank.com.cn:5060"}
        post_data = "indexId=0&showCount=20&optType=1&prodCode=&prodName=&currency=&prodlLfecycle=&prodRiskLevel=&subsBeginDate=&subsEndDate=&minExpectIncome=&maxExpectIncome=&time_limit_min=&time_limit_max=&incomeCharacteristic=&transCode=P220002&Signature=B3933D2EAE97536AB24707E1AAC541E6"
        r = myrequests(url, headers=kv, data=post_data, cert="client_keystore.pem", method="post")
        if r:
            print(r.text)
            response=r.json()["rows"]
            for item in response:
                nbsbm=item["prodId"]
                cpmc=item["prodName"]
                cpdjbm=item["debt_regist"]
                self.get_jz(nbsbm,100)



if __name__ == '__main__':
    hai_obj=HaiNanNongXinJz()
    #hai_obj.get_jz()
    hai_obj.get_page()