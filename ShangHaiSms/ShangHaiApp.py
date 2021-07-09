from pro_bank.tools.Reques import myrequests
import json
from pro_bank.tools.GetMd5 import gen_md5
from AESHEX import AES_HEX
import binascii
import gzip
class ShangHai():
    def __init__(self):
        self.kv={"X-BlueWare-ID":"NDhyJgoRNRF8FGwBAEsDEigoZRQ=",
"X-BlueWare-Transaction":"GlwlFyc2eEwQJDZiAFdnXVhfYhhYR3ZXL2FpE1FybTdZVjMLWQwzTlRcbkAoPSgVVxInNw9AMwkeBzoXNQwjAStwYAJAMzB6Q0cgAxpMb1sDHXYDKmdtRANxNG9YB2cLWV0wGlVGI1orMztFUCBiY0MfcAMEGDoSBCwnDi8mMxlcDzF0WxE6Hh4ebxEVCjIRdA51Kh0rNzcPWHwIBR02VwIQHk0dGhc0Uyg+Ck5DJwgGBzYlTg83BzwrHB9cJzs1BGMgBQ4bNg0zHzYLIXw+GQh+ZQpOUjwOGAE8HUNSYAs+Ez4SQCMmJUMJcAIeGiUKWyJtPmE/OBdcLXs0DkAxRAkACVYyNg8gLzwxKh02IDQNWjE2RR8gHBMHBAsgMzQVVxYnOQVGMR44DyEQDlAmDWwv",
"x-oneapm":"MT_3_1_656766532_92_%E4%B8%8A%E6%B5%B7%E9%93%B6%E8%A1%8C_18b24814-aabc-47eb-a818-d384210e96a5_2_518",
"Content-Type":"application/json",
"Content-Length":"358",
"Host":"mbank.bosc.cn",
"Connection":"Keep-Alive",
"Cookie":"SESSION=9ad3eb2a-ea51-474d-b2c0-be5bfc9d942e",
"Cookie2":"$Version=1",
"Accept-Encoding":"gzip",
"user-agent":"android"}
        self.key="MDSkfc7Om1B7cadj"
        self.iv="YTSHBCYTSHBC_PNC"
        self.aes=AES_HEX(self.key,self.iv)
    def getSms(self,nbsbm):
        url = "https://mbank.bosc.cn/SHMBank/public/financeDOC.do"
        post_data = '{{"ProductCode":"{}","DocSeq":"1","transIdNo":"0703"}}'.format(nbsbm)
        second_part = self.aes.encrypt(post_data)
        first_part = gen_md5(self.key + post_data).upper()
        third_part = "mVjUVE0OYEM9mLAq1lc2i9U13Rq7IGOnO16xzBOyln/LHUL3r2k9ijIFsDiHSuQlzdAomtFwstnpHckl+w7TYq6XThT8F3dtXT+3v3hVVEzXDLVRjksvzTuvGcenKqEbN0hnzDkSle6HFffujpqcA7Erd2CJev5WIFqqi1fY0fw="
        post_data = first_part + "" + second_part + "" + third_part
        r = myrequests(url, headers=self.kv, data=post_data,method="post")
        result = self.decrypt(r.text)
        result=json.loads(result)
        pdf_name=result["ProductDocName"]
        pdfContent=result["ProductDocData"]
        temp=gzip.decompress(binascii.a2b_base64(pdfContent))
        with open(pdf_name,"wb")as f:
            f.write(temp)

    def decrypt(self,response):
        substring = response[14:]
        iof3 = int(response[8:14], 16)
        iof1 = int(response[5:7], 16)  # 交换顺序的个数
        iof = int(response[3:5], 16)  # 修改的index
        iof2=int(response[7:8],16)
        if iof1%2:#非奇数减一
            iof1-=1
        change_part = substring[iof:iof + iof1]
        new_str_odd = ""
        new_str_even = ""
        index = 0
        for i in change_part:
            if index % 2:
                new_str_odd += i
            else:
                new_str_even += i
            index += 1
        reform_str = ""
        for odd, even in zip(new_str_odd, new_str_even):
            reform_str += odd
            reform_str += even
        substring = substring[0:iof] + reform_str + substring[iof + iof1:]
        hex_data = substring[0:iof3]
        result = self.aes.decrypt(hex_data)
        return result
if __name__ == '__main__':
    shang_obj=ShangHai()
    #shang_obj.getSms()
    nbsbm="WPJK18M1249"
    shang_obj.getSms(nbsbm)
