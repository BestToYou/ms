import base64
from Crypto.Cipher import AES
import binascii

class AES_HEX():#加密是输出base64，解密是输入hexstring
    def __init__(self,key,iv):
        self.key=key
        self.iv=iv

    def add_to_16(self,text):
        while len(text) % 16 != 0:
            text += '\0'
        return text


    def encrypt(self,data):
        if isinstance(self.key, str):
            self.key = self.key.encode('utf8')

        bs = AES.block_size
        pad = lambda s: s + (bs - len(s) % bs) * chr(bs - len(s) % bs)
        cipher = AES.new(self.key, AES.MODE_CBC,self.iv.encode())
        data = cipher.encrypt(pad(data).encode('utf8'))
        encrypt_data = binascii.b2a_hex(data)  # 输出hex
        encrypt_data = base64.b64encode(data)         # 取消注释，输出Base64格式
        return encrypt_data.decode('utf8')


    def decrypt(self,decrData):
        if isinstance(self.key, str):
            self.key = self.key.encode('utf8')
        cipher = AES.new(self.key, AES.MODE_CBC,self.iv.encode())
        plain_text = cipher.decrypt(binascii.a2b_hex(decrData))


        return str(plain_text,encoding="utf-8",errors="ignore").replace("","").replace("","")

if __name__ == '__main__':

    key = "MDSkfc7Om1B7cadj"
    iv = "YTSHBCYTSHBC_PNC"
    data="4384FE8602C3F5488C489038319991E4D9299F0B2CB266D038ED2F08582C303C308CB0BB6639DC5A6DC40D12D6EA5394561609F763B95C6DD501272F3F855C5537BA1AD88318FE2681091EE687A4664E9FB9F8AEC798FFA2A10BE949B10C23EAB62969768F6273FEE653F99C713BC75CACE34E06F84A96FCAB9B93AEB36957925E48AB80C192E62ADA8683A21772DBACC210577783E3B11BE4F61896006C3D045EAEDBE18307066BE4755532A5EC210785E1B7166321A798D6A02793A62526120CE277FFDD4FE86F580C3ABAC443EFFE27BD61998C08C0110F62BF4CFF5DB7D8CAFD8820AC0C156D17DEE3B5B3F365F194AB599C82D39CD23E1857DF72A7577DC5D4F1422407AEE293EE844A06482736014D48AF8FD66874AA6F556A8A2005F61891DB10D31F6C564DB3A14D3B56FA2E20CDCB4339A3DD7005AB8CF183C35D5D8492B279D6445D58473B0AED91A738F86590CFF6E471144618E73C5CBF1B5947FCD1E0AAAEAE33169B55BFF092B8F0AF3708062EDBB0DC5F0B263F1FC77E5E7E3033D70A60DFB226CA800B4F4647E1D7CF3F8B3252A5150B72797DD156354CE3131EE87F3837A3E07766BE8CD93C4120FB8F4E4E3A074362F4C8BB129D8C466016A317343458E7920FFC5B590AB4BF13B65DEDE204905524147F92131EAB42C5C363A1E5FE12485A8BEA451885B1C105A6BB1C611FD8309090A6FF6A1D0696CF9CE04866AAE0CEBC7A948802FF4B74EDC580FC98223B9A403C33D59830758EFD1A0D5DB9C9BA4778A9424FA3812AF3B6980ADCC3F00CE765A7FECA7F7FCC266125FD2EB6C9BC2AA9237D7CB0C57811E40AE26D95D59C5DA063E1A2D8FC87B54D878C4C218B7427256C86DA889903627226D8F71F6F1C432654E901726D4832B4EA58471B981A6D822538EBDD621C0D9241842F9AF43415BD88ED1FD5090ECE76DB25A4B12AB2B3859DEC790D063819F71741DCFDC25EC8D2CF5688F947A9BBD62E7F5F6C5E74796897FE36F543BA741625A3A0E3DC5CD719BEC3BDCAC17E1B935452231A3E8D94C41CB616B25D97FE50F9B9E3F1DF2DB373279D8E2C2500ADE5C17B298D06A3880B6D4BC3905BA8A6957AE3535FDED7475773D16A55C07C1D56E28C2CD4E6C56C699318FD66632C09E255E6BDDAD896D6F548E4E2EE70E5886D7EEA1E0AF6BDE4734732EB9DEA1C7907187DEAE08F1FF2865BC1EEE3249D909C44A59D06AB02336DB221C206C8040D4BAD37DE7399C8A42702520BD585EAF3EA76281738D3277A4AAE0BF27CC9EA4B844184AD3AB60DA9AD8F2CF167AADE16B3D4C4C11754AD359D59C13991B87FB00939A23402F9E5C170587648D241ED95613A5BBA6EC99634F4B37D9DE1E6947A926585EA08CFA0DED8B429956801320D59475736FE8FF694AE507248157182E3CE4BDBAC19431BCC6EACA5D45FA1F517314113C9BDA7D477EF940D7B2D24A8078A249EBEF1A5D945BB1CC9F0521AFC395E16EB95C1459D63357BD1AE26D7E22577E708D926CD45F63A7CEFA2702EBA2F8F6FC6FF15795D14AF9D90ADD9D87925EA25243AE758C3C48370244B54AE5C12975C7F5BC42A000D1A7913608223DCA0B3C723F5A2B1A7AA36872C9335F90C68B620341E1A596B5DA6490BCA4F2179680614ED78E1A532B16A0CC52856F4724F11CB3411734331C3C17A29E183B0F2B8AC096CCA39D256477A685A3DB5A569DF43864D16A07B7A898E61D0A8BAA793871ABE7117056F988CF838EC1CFC669ACB34A488B269CD1D4D882D1A12C2E2962CF7E22E334936E6EB389629D19756EF6E197DF317562AD3308C20AB6EDEAE902EAED892DAA930FBB8CED8633785841A78E879E6AC3D05B7A344018F75ECA9D283AD00404016FD706F09FF551BA129865C265247D20BADA31C181C6C5778FD4269D8B3205031A6AE614F8A827016B189BEB11C02BFDB2FBD25D69D82201C6941E1F980852D8928842F4E6D27AA7056494C34F1EA4D96B722211551A0592FF5FCECD11620556FBC65B5103515E601034BB5EBC72827D7B8F7340BBCA4EE42EEA5603196843EBD3C134C43DC4F2C15FDCDDA38B28942319694416723EAA8A17EF4DC25245182170787169791BD71B139B987E13F7B7E319EDA945D2BB9A3097B7569E4916BAAD1368C00FDE18776E4B730FD925D90AE8CE6C735E36B8AD0DAC766409A1DA2893804838414C760FF584D33AED621007E507EBB20B7A00506183A6B782017868DD9E1E78B459319040910C84EDCF1DD2CF16D235C17796859287C136E227AB530B6CE5CF0CE2F8A5C4143412591EA2AA8D77B8FDB6A4045F96315F999AF92A2D159B529051E88F847EB36708573A5416D96079466A6A103958D01FF3F5462503414C29373DB7FF049A71E41E8FFE8D7001C4BAAC6681A9DE2ABEA981632EEA5884BA44469D6C32C443539BA7ADED5AD8A76B03C47EB5566161F013987AB01C46DC5E8E7C129D1A78651087CB0BF46CFDAAD98E1FDA99F2F00AEB699B2DDFCBD7318E7EAEAA319A09A9A996F68419420C42F58622E7C9C2E86219EAFA13969501AB0D7830511EE695628720A6FA6119B746F18E8719E2A2A1903DAAD9DA67B32EB311475D77B831BC12351F65DC50163858EEB8D15039CD0FD911F90FA278A89E248BC5DE2A0E54B4B6A328AC5880575DCDE8476D4F14AA344BBB4F346B3FF3D61AF7EE5C233B1EF1045EA4646293D65FA20FA483E9FAC8020EE240951775A4D1C4BA7EF307BDC1316529FF5E2572569C3F9FEC90FE84BB5DDBC858C38D728658D3039BAD9409FE6C679D9BDD9E925ADBF6816312B0EFEF3B711F7876A2480BA1D8176A0FD531407264886AF2D2E7FB6AF7343D26C46F58CDBA92598C4781B2B7BA0DAE879478D81E039F93AA989D7BC5E38B5A3DFCA785808492DC5A872951685A359A661C2348944F4181BB9405E60594658F4A38FCA4C047580B6684135B562CF72AC912223992A75B9F9A7739CB29F57653A9CBE8585CC20568D3045860A0EFCA581B0BA04CFAF134D25209706CB73C668F415C36CFB8DEDD07E2FF6140B795468E49A1D228F7BF3AF4D7E0791409855C0AA9169B8F99A38F05EACEF8DADAAD6774DA55FC40B72D3B4BAFE38D0D881A1F2E0F979EB82BF4BC4F777C46B083100C25D6C7075641FA4AB647D856285EAAE2EF6952244D93C0EBC2B8888D7073D1129C19E435C293BB0017764B322D0A9AA18A5622125D4CEBCA52929AEB30A4631313B237EE3EC363DC0A0ECE9D0C81532D04A5142B06F81AE3A4A285C9197E643B04C0AA461AA9704AC404DECD46383951123A80771EB8D2285B0AA586421725D31982C6F51BD57F2E96079EFFF17C36CF140D4D95317865A1622361E03D1EF680500159643654972D1F544212521442E7454F5FFB4DFC5AA8568353D567834C4D5A5C50206C17F76091202C2E6BC38F21BB398A49EF5C6561980B39A9D2CDC2832560FB94F64BAA4B17D6EEC3F56A4AA3FCF8AA815F336B1F0240710900695CD390F5B117CEE5DA2572886A089BA249844DC1A269439E94A235C1CE213AC6BD1846C0998C443E0C6A829D9CFBCA46C5F3F03A3A5E05D2577A8F31B2EE4394646B07D653AFEED3EE09C13F66672EB45D19C024BB11CB3DE0C0F3AF0CF8E92D36E2BAB92AA6049C6F118DDE83E38CBFF40089C537079C059AABE45555E3764249238EB6ECE63890DCB4BF469374CD23528BE8C96E58AA3F94902C1A408D899314E7612C5D7D64A5C0DDC95416F4C556E3FE97D6ABB2E488ED7B079DDF3CA0701BB11222104254FE4962BAAE23671D0B6D2E9A1E13A72C9B98C47748D71A9B4AC0ACB60A79F36AA9AF238E6796104AEA0E4BB3AE4491CE43AE1C9477E5C484E107D567F867FC61D86D7ED068D7B96AC35E662DB9BA92806C70D88351BBE115BDA6B232F635349388AE222B83B898C16099208B292A1383553C8119B5AE3E3A120640C65908E79E11E0C938A2027E1FF0326E3667E5047CB4FEEC7650A4C0017C985D778D2F2813AEADBD7A8087995807CE76CAAD371B93DF99695A217507A41B88F0D2C2D0DD7DF3E14E8B17EA30F3DEAB1E80F189642EBA3CAF63EF4B3F672C7307B5024FF49AF3338282709DACA54040B254E6AF4C815E82A9DB4DD98994EBC192C7B6231515D97CEDBD5030686DCE3D423D6A090E7A2B6170BB72410C7E2FA7FAF0DE415D35EFF87125CB4D65E40F58C7EB0CB7F07E81951F4883BD764C70779850310D542A052E5E94D5C6D034F42B5604CABFF3E8DD371454BDF3C8BE2EB605C04A8B01A5F05680E62B3C3A636B7B0708D16864BA432338A6D62C52CC815D6C744A484BB7E3EE49A85425512359CEE3F3BC3A67DD7C5BD08872A2476D9EFEF3B66477FE8BECA282889038A9C717D05E3A2D63572FB5DBB56382CCFC4BC106ABB307CBE7461126326A06ECB71770F0C2579F3AD0C7C0A784687DE5138AE61F62E70E7F3DC649B3FF5FD703D2AEB6D30FA03145ACCEC3BFB667A2EAE8E3878A9321169E748F063A4B93E682C82139EA69292EAA55EE6F15E7A8B0EE22DCE444397DC05F24F6418D25389B478A392397F97B4997610873C55C37A768798B00EB3FAFF5317C44678CDBA427A1A7CB1B7CBBC9366E7571B9E9AD34EF32D5004F053710C2D015F6A8C55EA139638061B3F1762105E45C85662957338487DD0800D53B98102886775B27C92902A739ECE95AB8487FC617A6B9B2650BF335C56B94B93653FA8B6CE86302915532BAA944289807DC339B6596A7E8F32D98C5EC4C836D04735196FEC4AFAEE5BAEC36D724C3D9B14B79F57F3E6846E55F211B9B2D1743246A485D5B13FE482CAA8DB1E1391D65A752D161D4F2FCB93469C9073BA24778AA8FA82153461A493C98BD50443C84998796BF10C5BE6B2DD99A62C3E7DB878D8F240BADEF3A6DA28212DA8CA2E8854E1EDB3570265F8CDBC6EBBC5AADA16E9FC2A211307FC646C87425063914347176DD60B4A07D20A219CBE2B32EF6A677E4F89401CC86BBC33198B2CC4FD00BDB0B66CC9726824DF42AD19637729679D9A82849B6BABFAE8C26F2667428DE178DA66B767AB6B601688A4DFDA31946230B0C931D1CE9821C1C8AEBBD45032C802815993E8D3032FABA0CED545B0CC59C5C785E53D86DBD5994460471318BC5A8C2A2914E12DBC267A8CEF799999C41366EA55AE4CECFACC8CC3C159DC0A1933D8A18E8CF2AE5EF706D748BD83260C1605CC17EA7FF62631781AB409FF61BC7E4F6E53E39366103DE8D68AF4728DAA890C51D91C0B284E69ED582AD6A6C3F2AEE8CE12B3C20891768F6ACE55CF958B115E9D53F1A43549D74E794C7EA0AD36C0A5751007BFBE224637A9247B8C4D40C0499B80F43E780A924117F1E443696561A596C7D5A61C7D075A3A12901BD2B7E43CEC22F9C49D8EB0F1B1264C404C6CBC89C5DCBCE7B8D22781BE56CA7C0DE2312337E87D0495A84B5DCAE32224E1253FAB436213ABEC98B58844E9AB5FD0FD55BD7A105696F2DD12E88D9E0875FE5B61E1D313E77CA8B0E18A1F85945F2CACC242A3961B3A1FE6483036B219C8931114478AA1AB3CCCDEAA16A86BA9CB908104EDEC37A46560E91D510527B67D232A606D60DE4F1F542182048165A0CC5331B0ECF98A655AA8E24F4AF2F4632B183D1B60AAA965895CC1F5738A232023E020A50D6EB69E2D71015707182D3BF8CC14E524C77A000C518449C498DC2778DAC187F387DE6B1919B30E849DB46065B4B6A74EC1A5DC4DF526BA68C3AE257AA5DF5FFB0AD236E6AC1C84C6EC6690F39917621C3AE699ACD708ABAEE8DC18CE2D5444225CC0CE4A57BAC0BA7AAB123373846CB9D470EF8A046BD554E762ABE991B18C210249D33216D5D676BE1F295B11017CF4A9AF3077F567361B1247EB03620CBF62CFEFADB0A166798D2CF605AE7C5EF380AEAA793DC7311037C4094C71C7A60856E27ABDC5F8A24255E4A7E96D80CE336E46B794B137F2D328F6A21D5A7A18530D0E6CE237347DFBC07CAD5264A1E5FFDFD6F301C587AAC51906FFCE66DA92A1CB7176141334631290F8F53CED0D123269C7ED09B057FDE90436F972E7B1B5580C894B7294FD9DEF7EF92091C14183438741FF86C7EA7664341D9CF15ED7C323390ADD64E0EBC8B2F63C1EF88F92F2F9F0CB51BFEF84085197A6CCF25C514239833D955AA5A88AE5958E64ECD7FFA37FF72A109C3D779FC19074ADB802C9F19B34FCD24ADB73979D656BF9CF92EBF9AF1298C2CA7D6F2052B74648ACC273F4F1A319828F8D9C9164CE200E1B4E11ED2BC7CC064750C34311DFCDB808EBA734D3ADC5A76536845DB6023589E7EC0B07BE8A7447396B0A9C3F981DBAB566B86DD22C45976BF776C8D2C9491954837ADD9C83ECA0A5592366CD724A9C810282BA886712337890D0AAAC4A39F6CB0FCACFC6A6610E3EA3BA2BBE040FBF3D4168C36C28B1452B5E7FE9FAEDA8AD350F0022CD3EBA06F6CEED862C26960A23CB274C879F76275B0B52F765F05F12D96968EAD05742AD217ACF6E352EE3DA843D328E43422186EDBAC73D4B9532A0800E30B9C6FCF4CC50BF6192A055F881905EF207234D135CB57A5C605D51D64BC630C6A174AA5B9A746A735EDBC31BE51C08779BFCDD1EE3985AA74086C4F97D65A26C2415620DC7CD853EDFDEC61F52567F14F37032D8E962174BB22C33E9ECEC3F339475D3E6400DF3EAF44642C56ECBD3A6EF8A7E50C3937D40FCD7DACA0600E8E0560C185F725172866D6296EFF17819440E0BB5CEDC6B59A2F58295507C74EBB91D4C9966AACC57383321ABB5AAB46F6DEE876F1C816473E7798DBD73ED45E9B646416F0CF962E4727AEC5AFFC2953F4055D2F0E9D0936F3D9BD3CF799385755AA71C5C912D98340130AF2C03406C6849B436A344C477B601C1BD239D3CD4C04F6C143160C5EE019F301F6E43BF68839AF454D10F6DAE7B8B4C5DA39457E1AE5A3151344FB7006830AB126B05055AF772EFA5B1E55AFE4D0117487751A4919264A068CC6767D33AD73F99B33254BC2E5C965D5E928698B71128F6BFA60C74DA35D55BE7117501F0A9C039FF731833492A818135A568BA7098D9220B8EB918E12F6EE69ADCC07C1CFB69B00C3250C351989B1B75AC04439ED09961AFAB8582AC20F512DBF4341409EF87BC47EBA3F6875440581D5A46E24B00F0612BCE35A093E208930CB8BB92F8723E44BCF85010FC0D69ABC389D1E8380C1BAE3E71FB3B8B79104E4CD10CBC3182B157882550F9DFEC806D187A7FA0C5BA81ECA3650CAE15711D7B7F36FFA41BED7410D3649A2F72AC1632A51713D3DBF6725EF5AD8B074B82D45A937291F6108C49E449BBC4D37C8E600A0267A45FCD3358744BDF0B97794569ADA12EA439CF83DBB310B7B2ECCB8ACB2ABD127FF4EE45D37F8255436D3BCFE9E8C740E5AFAFDDF30556C86A526E7471BA26C8CFBD4100B3D1806522D6EBF8DAACA391F334BA2C9B676836AA7220BAF318E69072270FE53A12A3B39CE246BD280E9E8EEEF12BBD8F03FF8AE7A8EC2860537B1D68ADCC5F547E592D5EE963AEFF9B553BD88300A79D626FE582C746973E8828E5DDA7E90496DC8976E224148D1937666423A7D09E5467D31A325144AF727FA396E539155C60584F0E02E12DD9FD0B9B9D99A602AA681105718D3D17800826F1C941DA428AFBF547BF0353556EEF80F96BC43F9E99A1120886DC4B9DC4406DEFBEC1E6C92989033589CB7D4948B0088565DD6B32304CDB7F627E5977A4CD0F16E7826CFE43332357F5F6889ADD594142DBB0C382D0A44C9150213E995E62991B795C52EC2D27E6C75E11345501186CB0D878A76E752AA40EFCF6CB8E6CE713459FFF523129864D57528E094FEEC9F3E73313B7EA9DBCC146AC3A47E811B35F8428298BC59F594B7C9C6FE27F9583266583ECC97C266442E3E0FB2FE2C024F5672146BB3C090BF88C12D4A3B9400A87FC41D05C4D19199C3F5C05AE772938CB7902FDC29EE7E2B68DBE69D32D1421F99AAB229BC7B0F3E9CBF3192BF24E23B2FBE0A53B4FB25B5E02B000132256EC59435029050C273CD3CCB2D346677B3C953D822C88EB66C164DC580206520B4294C48D037DDBF86283F13B6A3549077707774F9A55ABFC7D6F636FA01B88211DAB0EDA087AD190B8CB2514C0AFE4FEA5FEF7A2309AA8CF272D5200E5EA43BB7853A3A102C2985CFC5B6F4FBCCD08F6DFDA2FB71F6434015C8D7B4F9F42B4D2994765D7DB330F6F39A6AB30D3D3B072BCF6A855DDDAE48694D8B2818F84E3237D0971D5D83F628BDD49F66DE95E33B2D7914B29C3B7CF846549485DC3DAD83B615F8B87648F5439637A98E32A00B5B558AA284C351488350655D048BC15E0418862A659CCBD850848DB03CDD5966B72B53F12A7AD357CB6F340ACA2AC34DCCB82C22BD98436FD82B0571F6CD9E183595284E86EF784ABBD9DD1DB6AF2E1EF24F4265817560C0CCCF7B51C78E8BC1418589E2C4D928F6D36912B0B9C85181837895A96DA534EADAE7171C8BB51CA02F0A396D5CBC4A2E556312D29D4DD4CF111002892E137D37611F63DBB921E601212621F0A16C1612A21056DB9D912CCBA15FC1A2C8D86A1690C0D5407714BF0EE1C387911702A7F266C5B18ACA5F61520142C061A81691361F133594079FEC348B53587AB4964FC6B0D35E8ED9049C9AD825DC4F60FD835F43A7C47676A5B89F0C8E8DD66900CAF5F440BFD201CADA28CE430B5B0CFDD74E72849A934BE68EA59D331C7559DC47766471DF921FDF80922110E692F8928FD8D33B09989E5A6C9661AABFBFE2CC6E01EE9908FB9D4EF2E51C3CC98762A1A0D192D75A4AA6016158CC222114C4DCB30D54BD2CF63CFD7CB069397C8DC46B4F48E7AC595B6EA3D1930586600A867C7056FE335FD3F57431100E853C1406F1A3E61E78AD5F91039E82821F8DDC0A74F105E5460D5C04B26FCA975FA18E0C152D6415EAD985E99F6B0BEF434140628B8AE4774D194B27A03D8803DBECD3A71517E2DA47FC2E64BE08CAD04D070EF15BF4EBA5DFD13825DD53B33952B94B82C856CE8CBF4E3703783E094CE3A44E5DD48C19D684587A1F6A256FCC32C8E7CD99BF68EC8F45E7FE4A266F94866AC6616623D97B4B852EEB47603B4E12CD317914CA409FD9FCAFF9C5DE0C13A82632F3E83D03EED063140ED3A0C4DE5C0B0C77AEB14B9E2F2A5F268022182A20A7D75938AA10101C9B51741C68328BBC087A6F62A5E7A5B05FBBBF381670028F045F5C48E17C44EDA73F417B6D5C866B37FCB8F076737C7BC2AA6956B49F5A3C6271F940CC2B16E173C2A2C14599E4414920A46CFFB35B0A75039C26A730BCB4737BD833B65BA24AFFCC2EC1606ABBA0C5D3EC6567FE61738A2D9CDA6A52C7BABD292AE63D34B4794E6F348FAE27B77193858DFBF11CC9AD4D009B32FDC7B6BE67CFE18A72872E0EC314588628EDF79E6BC8934A928BD7A3AFF78D8359838D020B8A069C72551111610B8A4CAD4666AC55DDF2D8D79EA0D4DC9EC8143343C6E142D3764A7CFD6AD6ED2DD6B84C769215B82B32D0C0C82F9E8F279EEFEE60A5E5B4FD9CCDCEE676B00479C4987EDDB41CBB1B8337885B6100625741174C57C0A02C4FCCBBF394B33072445540359784F15037E196E009B0F39AC6071CDDFE96A80D68CC7AD92F72FD45E9BD66795C1EE88E7F9CDFC1F4FE46783965B2D8805393A1CE56600F03752C30705D7A6887F6853811B39EFA4FCB558A40730FFD134594892F33E5FCB0270C4424C779713B72A8DBBB932DC02FF9047F34668B2F4B27175B6B110D894EEE2516B17F0A51D04A05E900FBEC3A39114E170075AAE301F66FF6C03671FCDFF71A69D451607ACE2756C07B36775EEDCF83925C4AD258E5EACF9E1BB252D04217ED564F4021CBA0994D1FC3FAD40609FED305A936DA236E3CE5F23ED48A4315DA0EFDA03047F1EDF6109AFE2FD92F3C1AD00A444514A5D6EAF9DF9D0330BF99A0F54361459D42AA7786E747D0C20278E2D70630D8722EFEA85E208A75C6189B24217D25EA2E4816B7B4513D71613700C1BCC80C5E552CE4BCCC90C6C33F2DE0B015F100C32F48BFA68B75E1A7AB4F2D7E177422573D6FA9FF87BFA712BFF05B8D62C23C29ABA2BB6AA83D49B16576C5541D0B825E387FC6C9456B012B8918DC23FB246E33EF9E6147A97ACCEFFFD7E91F32BFB4A705E6C39C4AEC2B6C58A5FC1B0B2BEB6BAEC3B06BB61E4046C3C5234C6AD8A1B5795675E419DDB44E3CC1F5C8288E0237A29974559A88723994D7581FB656FDC0DA53AB6EB36B56233994C0B8D443932A96FA475C714C6F09FFCE10F734B8B476AA417F4700C88AE251C3832E5012CBA195E2577F28D9D6E3417F9581593F462CBE4C115D8CFAB08582D4E879681F27E7BB9E48B645B95530B263476BCFD7B8F586BA4F0462F3821DA04836B81ECDC87025890FCF5D5A545292C164426E487739C2C0EF4AA75758EB82FB657B90F700E0834EFA81FC524AECD3923929EB8AFB0B7DE7E820805050F38DCD055BB90A9B63D4B82902E5D2FA93ABF76628B30863EAAE528B003F23F49D3CC807DDF779E3C93400D8AD2E322AC8BEF8B2A4598281E36824608F4E8C21EF067184B62085CF80B008A7599E3385DED6762A43046F195C11E2CA08E7717762CC51A2FB7187DE4C41D5D5CADAAF23180639B9B193C89024DB252E3C823711F3E78B51A4B56CA917DEBB185B4C648E2E77C0A68BCD9992BB77DEDD47CADFC43419CBB861C7C78E3899750ECAADEC1118C20C9C1077F42E9A7B37203AD66492E95A86E20CFD8EC6136F740C5F5E14F72DFA6462976B4A5BBB573A1109F7A92BF05A63AE399504E2F9E9744FE7F2A61494E8AC09DDAE0194B99E6C37D708FFBE225D31790DF1C38EB2591E375829CC9D3AD2B02D818F35A90AE512ACBF1AC83B5C8CEDAFC3AD1C71381B98AB4948A70F470DEB96BA73CA138EAD06BF9179C915281E144F2A7FF14328EDBFBEFD6575D7343FB0DEA38F73B9110FFC8E77B58F2E6E7C56E0DE7A18EB777F301F0CAA730A8421DB46347EDA7027975B26C3A45CADDA47D4B1E55DE52D0AD2097C229CC933A2449AB0CCF5043252577518C012EE0586018F5142F5E3793D73125495F2484744CD1AE1D09AE340B57D5979E005CB3CBE5BD0F447E06100D516CB6B39021FD86F7DB3EC1D64FFA5C2B13601BAC76DD4ACAAD3024E217F60544A266EBB97260CEA527107AC5C42FFF8E6929E9150822C6C4C4655B07CBE5804014926BD60A9A9C2F53AE4464414A5C4EF9E4A73F0E67D9979ACDB689C5251936093FFBE0D74B6875D6A2157DFE6EA16A7DED8AC1918E94CCA2296E4F96C985080A1E427691716927592BF53ACE3E399A5C8EFD44479CD3CDC1A0070103014E2D08373D3E08F9DB5521666FB466254E25FEEDCFE0CD2A8852563BFA61CE3E77695ACC3D9BE46DC91DEE9F0AACC25D94C254C3402D0FA0A8D7D3CE25CA9484A1E63D6173616DAC8451119F396BF7BA5AE5CF442F11EA75476E5CA0F1DB0458AC9CD0EFF1CA9825205DCFDC37F80F153AB6BDD3F2EBCDD5B592C46104D36E9533C663CFBA023D8C0B0B34208EE3F0EEF8A511EFCCCFE5580B0AA2D4E7EA83FDEE222D5562C3E8BE9BE6D25950E14CA8367300E106F5FE7E811342E9CF0D30B35CE2E1A2830BBD3C20B647A0BF76137B212BFD4CD556FC1F2F352CDF560C5007F56ADD7E82B6F9CEE1B36E1D95DE43A22564D1BA82C1E9881A2D5D35DB5A88E3FF31F9EF8D93B9BA60BF6C7D96788D8AFA3F612B41659A9B52545B2E31E3614F785B658CF7FA563D96A4AE93563B15C4B60E708D65433BC228F166CA5F5B78E009F559A01E21F2308214C4F2FDB3754AAF8D24BA985135FCDD541AEA0413389D2D0DDE5318E84936D9A3F3A37C9CFFCC8794537D06172C2B4C82C0E588960EAC1C9EF20E60503D7FD2AE89E2B05142B50F200477F470AEC94D711F4A65603C4299191A9DFA1DC667716E8DEEC2A10574F3CC9D52122848A97C12492724BECAFB2268B582AB8372F821070B023B6DAFB5C1EE6EF059780A01F59507C060CB7A7CCDEB6E0EF894508E50B50FCC43BACC0E6F6D2082B427FB0ADD90B31EE86A1D61EE8691E130E951A6E45B779ECA9AC18CB4C0DCBF25FA3966FB442C133973D16C2B4923F087C56DBBCC36EDEA74DCDF6CBC4440F4E55D532B02137C06334075E746702FF97634ABCE82F8B6628A51EF19065A84383FBE7E0D019AADC2BDA5EA5CC824C31C54C4D2F3393D2C0DBC9D84BCBD628FFA1FA2C83AFA7FF0A3EFEE3851DF15B60CA0ED06987E1DB536257B6E4E8BF25EBD4B59FA10F28B18004F6B020B9A60AE5364A4688727E6407A070F3DA2AE1853D237CD70FB9BBD74F4EDCA30003257213D01C9F742CC0636D1F340ECADB5DBC108BDF3093D5744E8D47EEF2EEA9AA81DFBCAEBDACBDB62869A42433992ED80325C49B26E1160E473ECA5737E9BC9AEA2D1E6107A029FAEFEED6FFE38CEDF565677377277303996557146C75E10A2C745F2B7B21A7EE7A570B3143C6939D5EAE5C932E1C3C82F2791052B8F6572AF207E15A5FF4A66FF28005586A58C7041416CEC428589F0E97F9AAB0DB1B7809FAC4E4E4D20EA4D3B2FA05A12AE60ADB75432385AB389EA1DE3D43405BEF7B2165AE37D25A7B492D9E368BB11C0AD43013984671C3BE0F4306C54B1F77654A9B8086B569B1DCA26E19F74DDB7DEC5DBEB5BF268676C0192DD1831C6B518AFAF251C50EE584545BF3D89B6263AE867BC0273DDCF1E121A3A2B194E81708822FB79396DCABA89C9470616A87F707D5F24358B905B76EB96F9C63469DD2F4563A71DA1C0E30009E8D4C09235F03EE6968C7704680AA12CA35F878491EEBAACAB0FB9C766DBE9EB21F51A640E73D69FE0C06E5D7D82967F17B784966EEE4DA8D90DB2B18C085BB0FD44406A055895CEC15EB67F556DF0E935040CC1BA1DEC4AAB596029B11752F03ACFFD2DA9CCC08421FBC004E2ECA06C029CB6F07527FA5470BB4F3483BB62CC46D619AAD04F09661ADE8DF22B98B670F3FCD53A5F3A17CFEC3036D604DDEBCD8D8015990CD8D3F9D14077D18FF19EC1E62B75447B35A90775AE393F207C49FAA1053ABCA4A9E1A5AB0653E3B6782AE49FCB896F3C0EB8C21546396FF404EC815676B2BB301046A32150B9B21427D58D783379CFFCF3E80A18EE169E46E98535A1C9741CA19B540C7B35AD87A70FB8FDCD9D1A2011C3E609AB88073F726BB1888F59AC828B7138C20247BA7FAB310DD92CE7F5147E0E6A20BE8134320053E632397C4F759E6FE3F73A7C8978751D4E7A72CF026C88B997D1CE60544F0E42FC2FCEC5D7042914003DE6D3806E873B64CAE5B01E0C9C1E6DF12ECCCDF36A3DFA1B737F4A1A3B72067A45E75443CE057558A0000C43D9690AD5CCA0B425B66F73A0E77A8395214F019ACBCBD6543CEF30D16A070A8297113A3D834D9C4047C8B28B44E384755F4D950355A3B6E59209D98F1394508E21EFE837F27AE10D929ADD37CABEEF7BC11263CC494C33250171779A7DAD8D8498DB24B2C9CFF40E31B1A64FC22586A419B2C8D724485C8357D626D0D2D9D1DF0EA71080D0BA641EB50C8DF59259C0E8BB1DFD8CB5F4230790FD82373F6731083FA9E77E76E221202D0D9E60CE6B23A5F239AC28B9D8B5A80BC77CDAA80C2B294F25943E7FCE677DE04BA91B637AB6A470B2895FBF7E3218C96375DCA339B4D31D81578E175B865CBBAD25FFE6BD4BC6987DFAA087ACEA3AE59FDC689D53C11017B21018C830BC8FF31D6D884A6DA1443ECBCEEE2349E0AD46E1DC8F3A061C27D77F9B1AE3EE9D9D3D620CFB93FE9DA31272DBD60A043BA874E60B297A139CEB0326F2F5E6B173CBC73824215F82D13D48214EB72ED90ED287D0D6FCB043F68D8DB7539220C619C38831928FB4EB8DAC144A834BE0784D627565132EA70E80FFA0EE2B07B2B642AD33335F021EAA69D353358B488043ABBD83FF4206F999D6F31C7488D07DA7DF2D5DBF52C782FA1302F0D502D7B1F5C86C3AFE7EA050BB926702AE09D613A2D1E565A9904A48FD3CA31E22D642544C4F4DE3A07888FB35C3C08624AD88985E7AD31858EBCE89B176799FCBCD3675D6696DDB3433A974443921C54941D2D9A79C97196B2FE500A9340F62A70D678A93CC78FAD58C07097C274F973BEC4E4CCF0CC4771B1BED1E186B7511A2AC35CF2D28C7FF2235B0BA23310422545D42658CBA84F8C8194BE9A7603216D6E856519DB300A2ED07D24B8501EF30011B1BCF9EE7E44B802939B6BF0D117FCCAEFCC03C6F54FE17AE289608DFD981DF46F2DEF4EFAD85563A9722CEAA46E5CCAC1470377653E0029A408D36A18F573BCADF5EB2FF9735F64488543E82BF06531D8E6A7B1A4B1FDE88118E4E09F86D272630E5056A867EE9795BE939BB60470E1817BD3B14018FE726E67D94F38EC5192AA06F0095037D4D148B4D6F59069C5C95542DBBDB79C79E1966C577886AE3344AE25C8FDC80B2DAD8132EC00A39629694DC10EFA7059376F68A50898FCB619D3EDBE56F1740D0A841DAB553B38C6E52C47E43A449C451D79BF0A9CE8C74F83EEF318B7D8273E40A0ECE7BC532989AD9A97266B0408A815C5988F2875F8046BD29A1C70668DF32B5DA626F21AE066B398A0809E321A3AD0E4C6668AE13DE937ECDE310CFF696BDE073BAF392CDD64B7C1E251ED28FE506DE36A35637B155C2907B895AD307EDDD5E33392182D556232738764CCF97524318E74961DADFE40853B8124B502A2C883397FE8B8A0A56307A1CA1FCB3F66438787D7A1CF49140AD7C9159E82906C6B221630615C9BFA12247B1EE6F2F9B86E7D8D30E428DE91588DDFDD56E24174BE560C34AEAA344E8ED4B05E399BF9F316523DFFBABAF214D6AC3C8576E037D6099109B1F77394E0A666AA2EC3D8F29EF3C0E2C78B494DF94058F869CDE738CCABE80CB1F6DA767455ECFBE566C49BD6CEEE5175A0A32A6444E32F217D380D2F1D4ECE9D6195EED8657FE82F3F7AA15749A5C24A4618DE46BE529EF9FB59D7AB6A7EECF1E9861D01543A29F88765095C534516745CC4EEACE3815815ECCEF9250E03EE0EC26DDB6042034BAE6140F01EF3548E3189A1A11DB9E76C99370EAEC75153B02809B62AF0AE6FFB474BE59FEAF7860F6C4852F5CA13007EF5855CF23E9DE2A29F180B6EDE3234FC42748EFD277691E3067A06379BA3E8EC956A9E3113086AACF7D2EC8B0FAA8A4586686534C9A4F99856D10C0B03B1C4323C1E018BA9B8E40301E9E1C07EA1DC4EB54FE8DEA8115B4C85B033841C4316DF20D81F58A7DEEBDE4B085633A9778400C73CFB317C9795578C2918601DFFA9BDFCFB68911735AF69B80D6BF26962D23F6B2D6C992ED6B387EC6759E64DB03B9BBAC26948A0612775A5BFEC993AFE3D3B239B9CE13DED38797EFE2AD58B35CD53740F3DCC8AEFC59CA0A7A293C58CDB440963D5C4E5253C7C81C9002B0DDFE678E69C15BF060FE35ABFF6CA1404F61F33CC89709D5472061B61EC68A36785D281FD3AD74B81383A1B11118C01B81C0D1C6D350355583C1FD06A9F679DF3F3B8CEE60CEAFE74B660A4AE46E80C5BFE1F8DC81AA14C50B349D58B0B51D68F456AA8ABF3B0D35083A47E8D8518EDF23A7762A5080351A50CA6B39844B14E756E5A6FE0A2307A06EB71B26CC1F119DB6D139F6C8A73291E76EA9941D80515022C075CADD48265261803E5F47CF87AD9C9A01FCABF9D03D87641ACEE34712F44B6AE61A3494C376EB08A3E078B6E55F27893B2944CA37118160CB7BF89AAA310A4DE7B77807F6A3CEA48C5AD9CE971E578B79B2E5F62461338B1E3EA677BC0E5302AE6E73856AFC2873FDFF614F395EC1CF382EB765262E432423881EE7ACFFC2722BAD9FCB705BE81C46D611C1180022074641B6C6F0647A6C594403C1779DFF079A8F664976343B63E02203912EB060C92CB21A27D5C7BF4D7A586A06F90B853FDC9A863ED6402F3A30E3F965073937DAC91E1C42D5C7B11F6594B9041725B264674E1F9897B7D47AD00280FCB31D7D1F79B5D94FB5A856F8216AAB9FF9DE28BF7FD5493963AAC5CECA7D9EADDC33E793EB9F42B4EF14AD5C158B67637BF6C4871E3EAC028604A9D703FC1B553D8D61D3223226A7A7C85FA2A05D79382FE6FC52A3F3A5307110F534AF3482F3EEB00EC27F4755983A9ED7420DC053D7CFD7067A45B8CCA20E331DDA3C452ED0B369E7582D531408BF092CEEA6A61A95EE25F0696CA9B15E5501CE390E9E0F0F420B9855C4D5E3D8531D9B26F66F2747F79ACCB6B61BA6BF18C200501F0920D5714DCCF43DC109340401B73A99055C051E271DF966BDFD7BD96FF3FC13EE8BEA3BD582FC227F0033DDFEA6E4FDDC27364F263BCBF0C4831C7F9117E21CDC79633CD842E88EDEE6F42FFCE6F41D95B1B710ADC6E2FF97E4E857D84D03D0E9A8339DD4F5B0B64C2EFD1E2039DBDFBC0D17573C127B66B15AE39F4F31FF92292E59DA84A8D7A5E7EBA385DCA83740AF221EC96EDEB3A0C2FDB4659BEF82D6CBD4E2780C49AB5148B7A61011A0DA9AD2886ABD122B955AF94218E4D23A9C8024EDDE47B065086DE596F68644E0E7A1328B3EC9A684BDF1DD407013FFFDA96CC2964C4E9EAE210CB9F7F2AB71356FB725D0976268E60D0D74387EE3D55B13B36CAFF9952E2577B22A00BF2612925F54D51B257BCA469E5C26E763B0BCB87120E5FE2EAB5D34A0E2904656D673F08C72CD95CAE9FA96F673612701DA2E5965E82CEE660A9E76EA9A5BC1730F53825445D645462DA733BAC002AEB02B41BA42B183D6ADFBC4BA5EADC4036341776002AC07EFBBA525253EE86991E519EAE88A1969B29880D7362EAC0791F5E74D8ADD710EC484ED975E812A857195F21DDB9A871DDABDDD6407D69971E5F05D40A0FD09816E7095ADE0D26F8D141F3290EE31A55FE50A3B9C419672057B40879FFC383EDEE7BACF325D78A76917D529A17DE66EC04D9ED62F930B7AC9A8B42440F6277F400C6A8A5FD2DBE77709EEE65C9A867CACA7B50389CB5D087D9BB832D8F8C33E7C1339D79DA42530321998E80523B54A8EF9D237C644D45498D8F23E838ECD4F33B8D3C5229A1BFF2A6DC992ADFAF4BD8A27FB41921C81AAD0E2ABDE620021B4A7D758B7E22BE22970962B5B26C229835FED6ADC3FBAE91AD952C0F6D115A50F55ACD8780B7009573C69C5E022CF919A5F22291CEAA75F92BAD2C1CD1DDEBBD15BA3204FA72AE9F8439786383B47C3AE1BA1740A3E8A651ECE54EBAE15C751A13951CE186A5F2693DD3F92A35248B5E8AA46A07AEB702E9E0768FF3055BB04ACF45E968B4DEE4FE658B3852DFCA76079E2670938322CDB764D3A0BE61DF4B431D9F641B37C06BA5565F1271295212D4B67D6F09E042531A8FB33FF99FCF2340B578E367941F6AFFE25D03D9E3424B5E25CEA93276235CE6034ABF5E6C0CE9EA3E3586C22AEAFB6848D969F90688DE27832F2F28B47BDAB026D4AFA9FFD4FA6370DE5E62E0A2E876A034DE1E66089485F093C611F8477078EB5858BDDD33D7D4C0F418EEBCE74F409D88939BA196E5085AB3ACEE4145A914EAC1D33C2B25401148E8C35D02B7C044DE99CEB70776E6EE021CF803B33DFEF2D52EDB8F4F1B24F10715D8324D8F92C4B0082A7DBEAF1CB22DF590595C9CBFBC6DAA5DD19E8257359E5436C7FA01384244A1A0A8DFA521056B4667A5EF41233DEDD03DD0F0A46FBC20BFFC5C8C799ECFD70E3A301ADB4849C9710ACA99EA256E4013E315F0A5A826C5E248878251DD8B46E673C3793E8329B0B30C1789D7A81FDA63DFFBFC76DBAF66B260E5118D2923BB0D0A09BCD58D4F5D74EB26D6F6D94E3AA1977BCE4EF0E166A923B50FF19E79F813FBD3F86BBC32D42AD3FA91B9D4BBEBCF784B107BD98A84028A5744558E7615CE507E15224B3F39CA54F03D323C9EC99F076945915940AB9E27024833328D43705F6036C722699004170B5D442364DDB2B77B5CD79FAE66DF1E3BACD628D4E1490CCB9A9422B02D01C7E4CE8A6758C23F961275108ACC221CB61F523FF52D4A54B071778E458A25F1F59B85608AA53F1D8E799E131FEB16FE57693648022D90DFB353C5E43FADDC73B97B9088EAC9DE31D67FD7815E0420DED12DFD85738E646BB4F25F8E1537939F0512A02F51B70E4228135CDC283105AAB1E9BE621B91E1F52D537520146E43C0AAD905CB64CEE36046832D76C143D9DDF20DD714C0482E5BFB4A4ED9EA55DC2D3FFDF66313A8FA34C04A1AFC69DD51F76FE40DE59A6DC3F695FECCB6015E2C3A1F66A737B18603F9EF917A00F9B6FA7DDE33C6374A18BCFE2BB07ADA9011DD5128DF3BE646B8AFEB0B6C053A0FE23DC1758D25210B08C4EFF700204A187B3827D19B3FB985FA2D18918DB0CDDFB537A05C8FBF61D9A55E333A6BF638B7D49C777B0B8604C0AE6D1FFB2BBE70DC644983D2F1AA08B4AC82B64E62A7B8846C516480462EE7E130C6BD487431A39F341DAB76F1B0F98BB3FEFD4A275D51287FBD84B774D4DDCB1246AC09EA80BE949B382CDEF902FAEE6A97168551D5912F12BBC57C147C15637084D6DDE61FEFC672A0870514F0D0138071143C6938FE9F3918BB92A4E948D1ADDDA0D5E2C58DE4E2B010C97F9E34D7B93B5014CFF9A04E6FAD450A2E1F215D7C8C305219D5EAB33CA74A3C006209F11E76D4398133C371ED52F6A48519558EF9421D0439A4F1ABF979F362D7E1BD112C0B4382C802B871C0C7E902B7A4B02AECCABF97EFF611794D046FF5D67664DAF8C5AF7B7B856193FE1B9607FD5EB2551ABB6538907FB6B3567AD26F9AB6E6227FF51021574EEF0326B687DAEE1DC6047FD148FC3F4BF4EA8173F2B6611D576623ECA5232448247CDB83A2C8EB8A33266CF1B70423681B43803007E72C928520FC96071754AC2E3D3681670DB99941D92AD2EB87F8524F7678C0DAAF1C0F20E625F2C6B06E1E2290C6D840BCEC0B576ED2F170A70E1704B152E99829E12A03BF31808C501CE84F4FA7F75FD563DB3CFC9C4C1D2D1A1582A4433FAB660B636C1391645809C1C9E9A1AE9DC212586A3EDECC0B265B7EA40EAA2FC758D61FE947118BBFFCBCBB232918D49C67AFEF070024D4BAF6D8F2C20016D9FA90675BDFD7A3C25FA51E821D8AD5FB1778B09B322E1343DF1EDCE7D71AEAD7BCCFA248A70B1AA11BECA778E18CDDBAF9B05393CEAFAB0F28A6A67811102702524F5745A5262D94501AFA5D1659C127F8354288CD34ED75B6CCEE29F8C59F63920CE00C0B0C312FA53EA476E60E1F7512DB8B62032457BCA965B686A4CF86C07D898C3F53CAFF5DF2764AB4B4AB5B663D25CBBBC6398DA7E739F1D09E5F914700BB003AD43161133DC051469CE550516D2FED88D23EC8BA6080DE08CBDD7D6E9F94A60BE93A3E4B404108DD7DB4EE2E5E3F0DE9FBCA30056E7F5C86950AEDE98C1FD62C9833C191E21A5D13A5D67D9542B3D9E42E0B790116A4BF2CB9E9EBAFD1967614B95262AB88252D7A8548AF84BBF5B020322D74B6F34E8AB53E5E5D7287E0EE951C9C2BE3D3936819FEB9A02B813906FF52F466DE110718B60EE2314DACBAC67E87274CDBCAD09F165ADED82288560C679F66FBA093E3839326BAB128EBAF1CD1C39EE15082C4398112329562F7F5C5F4B37CCB5BBE60834AAB675F4DD3F53D2EBAD8EC8ABFFA0854075B9F8EAEBED1792E6DA35003485B5FA5876D5D1B88E16A94952414E4141C5734F9B4FDDAE97C03EA08EB5BDB1E90F24474AE38930EB1185D36DE7037BAAAF0EF6B4EDA9CD49CEFD59A1AA43C301299B0ECA74BD44473A1CCACFFE708C89898714F9DF77CB1654DF2469D6A0B95E6370B6DA2F634928EA549C71B08F4F2F8C2F6C5E2E872208413D50381626FFF3B5CB48943464268B28AC0A84882823251BC0E4BC3D94187747F5D0A36C11C0016D5877E94A43A953B1605F59D4DD76F7DAA9DEB71D33AB154DEDA61F72EADC8828DAB500712A6091147A8F7C76AF6541AD744B087F682E12E62B31D68FEF88944D9BFA9D8F9E93488529CC2F13D4EFE704CFFCBB49B561EBCD69487834D70D7DB5AA4DD008C64AEA066DEC3F9DF8F9C42F6DE648AFE40EAAC55B5338675D2A393EB906738FBB8B4252CD06E75556C44A32FC3A8C808561E32DAD2FADE7F1911B6BE188761275B53A17EA6246887088FF6C5BABEAF6F39E6F79B364B548E7CB4CF08AC871CE76F5D21DD386D72E0D64BC7471B6185D73000CB5B76F3A536FC70AA73CBB37799358675B710ADF8D170223BBED62F8BF6C18D05AB08727BC570F729F357AADA1D4252732E943E4F1FD559F62B93EC941AEFDF4E70610C61673DDA991A8D2407F7C1045EA35B4B8FDAF974149C2340F741B42AEDF63EDB0B862D1C33236DFE89AB1726D2BC627334BBA5A52574B0E8262DB14711F9FBFF2942AC06D2314A2ACBE3B6C98A2595614115EB7BD68D8D2C90CFA501DB7F203F086FD5F5DEC469452DD7B633BC7C02FE43AF1B02EAE237E4CCDF398DEB51BA2D4D3C9C5F67A152BEF2E6749C74B2150C58C54D242F7F88C43B0FBADCA2C13EE6B6B65C93FE22FE703827110987D2C124678BA0D8D3B6DB5ADB10C71362844E901C6D30E7BC78BEE9945B268D50FCDC906A7D0A2F2675E84DA9908F6B26ACEA47F814571B2DA8615D37FAB79C1FEFED68E540B0EC6634E461A71F0DE277960B53F0AF252DA205C05F93605B256158CFFD4062CDCB0ECE3A64D6953434AAA7B01C4A25A07FE3958B5407F1D9F659540C823340B10465F990038139CB52EE44CE2E8D771C9A2C438D90818166F1CB576B85BC9BBAF927B17CA975AC7A469CA1A859487BE3B0761AA3EAEC9A42FAE708C2F44CFAB8D409816FB2B5913BFC681D81D5AB5BC6E82E5ECE6CE9921FB3E18C18733DBED036CABC73F839159EA7FF44FF9A4FC44504ACAC75D7857F016337F5683ABA386010E691D6F38FEF8872410F141B648D084D0A27BB71F898F487981B2B9D9EA5ED68C2622FB73821A8388ABEAB484AB0FBE146DFDA1AE8A8877F79AA026C0BF85F540248924C7A3C41118D05F6F1A01C252874DB5CB944955C6D026077821891B3EFC6DD3A2C2FEB423072EA505B116687C46FF17A1B25A4A62F46854AA2F36C9AFE57150E5EB491AC53B579DBD05B4C52305FF572E06C76DB788ACF90BAC5F83DCEE263944CD36CC2F5F14C4BD981ADAB6A1D8EB955868833F238878022F3BFD85B7810AB9C2FAE0E66B56B614443E0A"
    aes_obj=AES_HEX(key,iv)

    result=aes_obj.decrypt(data)
    print(result)
