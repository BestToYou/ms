import random

import frida
import sys
import time
import json



def on_message(message, data):
    print("[%s] => %s" % (message, data))


def start_hook():
    device = frida.get_usb_device(timeout=11)


    app_package_name = "com.yitong.mbank.psbc"  
    try:
        pid = device.spawn([app_package_name])
        device.resume(pid)
        time.sleep(1)  # 2
        session = device.attach(pid)
        print("[*] start hook")
        print(session)


        with open("test.js", "r", encoding="utf-8") as file:
            js_code = file.read()
        script = session.create_script(js_code)
        script.on('message', on_message)
        script.load()
        return script
    except frida.NotSupportedError:
        print("请检查包名的有效性.")


if __name__ == '__main__':
    start_hook()
