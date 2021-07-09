from pyDes import des, ECB, PAD_PKCS5
import base64

class DES_Encry():
    def __init__(self,secret_key):
        self.secret_key=secret_key

    def des_encrypt(self,s):
        secret_key=self.secret_key
        iv = secret_key
        k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        en = k.encrypt(s.encode('utf-8'), padmode=PAD_PKCS5)
        return str(base64.b64encode(en), 'utf-8')

    def des_descrypt(self,s):
        secret_key = self.secret_key
        iv = secret_key
        k = des(secret_key, ECB, iv, pad=None, padmode=PAD_PKCS5)
        de = k.decrypt(base64.b64decode(s), padmode=PAD_PKCS5)
        return de
if __name__ == '__main__':
    des_obj=DES_Encry("86405655")
    result=des_obj.des_encrypt("eyJyZXFIZWFkIjp7InNuIjoiMjAyMTA1MjExMzMwNDI3ODExN3BYcjAyeUZpem9lWnp4cWZIZXFud0lcLzFxR2dCZ0QiLCJ0cmFuc0lkIjoiMVAzMDAwIiwiYnJhbmQiOiJOZXh1cyA2UCIsInJxSWQiOiIwMSIsImJrSWQiOiI4MDkiLCJvcElkIjoiZWJ1c19GaW5hbmNpbmdzRGVzY3JpYmUiLCJzdGltZSI6IjIwMjEwNTIxMTMzMDQyNzgxIiwiZFR5cCI6IjAyIiwiZElkIjoiMTdwWHIwMnlGaXpvZVp6eHFmSGVxbndJXC8xcUdnQmdEIyNBQzpDRjo4NTpDQTozMToxMyIsIm9zVmVyIjoiQVJELjYuMC4xIiwiYXBwVmVyIjoiQVJELjQuMi4xIiwiaXNDcmFjayI6IjAiLCJwb3NYIjoiIiwicG9zWSI6IiIsImlzV2lmaSI6IlkiLCJwaG9uZU5vIjoiIiwicnNwRm10IjoianNvbiIsInN1Ym1pdEtleSI6IiIsImNsaWVudEluZm8iOnsiaW1laSI6Ijg2Nzk4MDAyMDIwNzM5MCIsIndpZmlTc2lkIjoiTEhaWF9JVF9SRVBPUlQiLCJzaW1PcGVyYXRvciI6IiIsInNjcmVlblJlcyI6IjE0NDAqMjM5MiIsImJ1aWxkQm9hcmQiOiJhbmdsZXIiLCJ3aWZpbWFjIjoiYTg6NTc6NGU6NWI6NjE6OGUiLCJjbGllbnRJcCI6IjE4Mi40OC4xMDYuMTc4IiwiY2xpZW50SXNwIjoiVU5JQ09NIiwidmlzaXRTZXJ2ZXJJcCI6ImViYW5rLmR6YmNoaW5hLmNvbSIsImFwcFBhY2thZ2VOYW1lIjoiY29tLmlzcy5kZXpob3ViYW5rIiwiaXNoYWRYUG9zZWQiOiIxIiwiZmlyc3RJbnN0YWxsVGltZSI6IjIwMjEtMDUtMTcifSwidHJhbnNBZGRyIjoi5Lit5Zu9fOWMl<S6rOW4gnzljJfkuqzluIJ85pyd6Ziz5Yy6fOWMl<Wbm<eOr<S4nOi3r<i<hei3r3w75Lit5Zu9fOWMl<S6rHzljJfkuqzluIJ8fHwiLCJ2ZXJzaW9uX251bSI6Ik1CX1YxOSIsInppcExhc3RNb2RGbGFnIjoiIn0sInJlcURhdGEiOnsiUHJkQ29kZSI6IkRDRk0yMTAzNCIsInR5cGUiOiIxIn0sIm1hYyI6IllUVmhNamRoTm1RNU5UWTBNVEUxT1RkaE9HVXdaVGMzWkRnelpqRmhOVEE9In0=")
    print(result)
