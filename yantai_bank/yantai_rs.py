import json

import execjs

from tools.Reques import myrequests

from  loguru import  logger
url = "https://ebank.yantaibank.net/pbank/fund/ebus_CAFinancingsNoSession.do"

def getjs():
    f = open(r"yantaimac.js", 'r', encoding='UTF-8')  ##打开JS文件
    line = f.readline()
    htmlstr = ''
    while line:
        htmlstr = htmlstr + line
        line = f.readline()
    ctx = execjs.compile(htmlstr)
    return ctx

ctx = getjs()



cookies = "equipmentID=1089870f760e9123d16535a5f54a8b5d8beca13d11a61f24a7ff72807db083b3"

dno = ctx.call("getdNo",cookies)

print(dno)


item = '{"reqData":{"turnPageBeginPos":"40","turnPageShowNum":"10","prod_code":"","prod_name":"","prod_time_limit":"","income_characteristic":"","jined":"","prodAgentFlag":"1","queryFlag":"0"},"reqHead":{"rqId":"A1","referer":"https://ebank.yantaibank.net/pbank/#/finance/market","sn":null,"transId":"430301010","bkId":"816","stime":"20210625112203670","sid":null,"rspFmt":"json","submitKey":null,"version_num":"PB_V7","appVer":"chrome/91.0.4472.114","dNo":"%s","isPassword":true,"flag":true,"opId":"ebus_CASupermarketQueryPB"}}'%dno
item = ctx.call("getMac",item)



data ={
"rqId": "A1",
"jsonData":str(item)
}
print(str(item))
response= myrequests(url=url,data=data,method="post")
print(response.text)

