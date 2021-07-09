import requests
from DES_ECB import DES_Encry
class XinYinLiCai():
    def __init__(self):
        self.kv = {"user-agent": "Nexus 6P(Android/6.0.1) hundsun(com.citicwealth.fintech/1.0.8) Weex/1.5.0 1440x2392",
                   "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                   "Content-Length": "81",
                   "Host": "app.citic-wealth.com",
                   "Connection": "Keep-Alive",
                   "Accept-Encoding": "gzip"}
        self.des_obj=DES_Encry("lkjlj2ws")#写死的，app版本迭代可能会更换
        self.client_id=self.get_client_id()#通过app hook发现存在过期时间，但服务器好像没校验，过期也能用

    def get_product_list(self):
        url="https://app.citic-wealth.com/appServer/product/product/productInfoList.json"
        raw_post = "pageno=1&pagesize=35"#一页不到35条数据
        raw_post = self.des_obj.des_encrypt(raw_post).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        post_data = '_p={}&channel=app&clientid={}'.format(raw_post,self.client_id)
        r = requests.post(url, headers=self.kv, data=post_data)
        print(r.text)
        productList=r.json()["productList"]
        for item in productList:
            cpmc=item["fundfullname"]
            nbsbm=item["fundcode"]
            cpdjbm=item["debtRegistCode"]

    def get_jz(self,nbsbm):
        url="https://app.citic-wealth.com/appServer/product/product/productTrend.json"
        raw_post='prdcodes={}&queryunit=12&offset=1&querynum=372'.format(nbsbm)#查询一年的数据
        raw_post = self.des_obj.des_encrypt(raw_post).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        post_data = '_p={}&channel=app&clientid={}'.format(raw_post, self.client_id)
        r = requests.post(url, headers=self.kv, data=post_data)
        print(r.text)


    def get_sms(self,nbsbm):
        url="https://app.citic-wealth.com/appServer/webapi/product/queryArticleList.json"
        raw_post='requestpageno=1&requestnum=10&tags=%E4%BA%A7%E5%93%81%E8%AF%B4%E6%98%8E%E4%B9%A6%7C%E5%AE%9A%E6%9C%9F%E5%85%AC%E5%91%8A%7C%E4%B8%9A%E5%8A%A1%E5%85%AC%E5%91%8A&fundcodes={}'.format(nbsbm)
        raw_post = self.des_obj.des_encrypt(raw_post).replace("+", "%2B").replace("/", "%2F").replace("=", "%3D")
        post_data = '_p={}&channel=app&clientid={}'.format(raw_post, self.client_id)
        r = requests.post(url, headers=self.kv, data=post_data)
        print(r.text)

    def get_client_id(self):
        url="https://app.citic-wealth.com/appServer/common/msgpush/mssagearrayquery.json"
        raw_post="querytype=0&direction=0&pageno=1&pagesize=10&deviceId=453b41a4d9111fee4b0c1b031b377c4b3917c4221cb77e001d61b169a471b82487bcc4d28d3bbe2a36167a97416"
        raw_post=self.des_obj.des_encrypt(raw_post).replace("+","%2B").replace("/","%2F").replace("=","%3D")
        post_data='_p={}&channel=app'.format(raw_post)
        r=requests.post(url,headers=self.kv,data=post_data)
        clientid=r.json()["clientid"]
        return clientid
if __name__ == '__main__':
    xin_obj=XinYinLiCai()
    xin_obj.get_product_list()
    xin_obj.get_jz("AF20A2047")
    xin_obj.get_sms("AF20A2047")
