import json

from flask import Flask, jsonify, request
from main import start_hook
import time, random, requests
from urllib.parse import quote


app = Flask(__name__)
script = start_hook()


@app.route("/")
def index():
    return "/"




@app.route("/en",methods=['POST'])
def en():

        #data= request.get_data().decode('utf-8')

        #data =  '{"header":{"service":"sysDateService/getSysDateResult","method":"get","staticData":false,"options":[],"_t":"1601016471074"},"payload":{}}'

        data=request.form['cs']



        print("得到加密参数"+data+"得到加密参数结束")
        args = None


        args = script.exports.jiami(data)

        msg = {"args":args}






        return msg
@app.route("/de",methods =['POST'])
def de():

        data= request.get_data().decode('utf-8')


        
        #en = "11014CB200010009F6CD9E523FC65B990A8A93D528E293FD34E7BA22C1FA2564716F0B1DCE30544DF327446DF9ACE0CCD95E917A96F232BD132E75551FA16BDB600F1F2566AAA7958557727AA3FDD46145BBBDAB07CBF7EAC1D878C8F2EA46C9F61C710796B02A8022AD7A1CF8C77578FB0D8500AD12F1083F2FFBF63B389E1520719C06BF1C80F7AA2D6FE3443C8C"

        print("参数---",data)

        args = script.exports.jiemi(data)
        msg = {"args":args}




        return msg




if __name__ == '__main__':
    app.run()
