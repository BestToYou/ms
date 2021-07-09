


function isChinese(s){
	return /[\u4e00-\u9fa5]/.test(s);
}
function ch2Unicdoe(str){
	if(!str){
		return;
	}
	var unicode = '';
	for (var i = 0; i <  str.length; i++) {
		var temp = str.charAt(i);
		if(isChinese(temp)){
			unicode += '\\u' +  temp.charCodeAt(0).toString(16);
		}
		else{
			unicode += temp;
		}
	}
	return unicode;

}

function reqEncode(data){
    var result;


    Java.perform(function () {
        //data1 = tounicode(data);
        var data1 = ch2Unicdoe(data)
        console.log("转换之后的结果"+data1)
        var hookencrypt=Java.use("com.yitong.mbank.util.security.CryptoUtil");
        var instance=hookencrypt.$new();
        var app = Java.use("android.app.ActivityThread").currentApplication();
        var randomstr = "s8oUckXyyY9BwDFD"
        result = instance.a(app,data,randomstr)
        console.log("加密结果得到"+len(result))



    });

    return result;
    

}



function resDecode(data){

    var result1 ;
    Java.perform(function () {
        var hookencrypt=Java.use("com.yitong.mbank.util.security.CryptoUtil");
        var instance=hookencrypt.$new();
        var app = Java.use("android.app.ActivityThread").currentApplication();
        var randomstr = "s8oUckXyyY9BwDFD"

        result1 = instance.b(app,data,randomstr);
      
        console.log(result1);


    });

    return result1;
    

}


rpc.exports = {
    jiami:reqEncode,
    jiemi:resDecode
}