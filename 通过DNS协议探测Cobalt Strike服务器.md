### **通过DNS协议探测Cobalt Strike服务器**

​		"Cobalt Strike，是一款国外开发的渗透测试神器，其强大的内网穿透能力及多样化的攻击方式使其成为众多APT组织的首选。如何有效地检测和识别Cobalt Strike服务器一直以来都是安全设备厂商和企业安全关注的焦点。"

​		近日，F-Secure的安全研究员发布了一篇文章讲述了如何探测Cobalt Strike DNS重定向服务。其主要探测方式是向Cobalt Strike服务器发起多个不同域名的查询（包括A记录和TXT记录），然后对比每个查询的返回结果。如果返回结果相同，那么对应的服务器很可能就是潜在的Cobalt Strike C2服务器。随后，我们对Cobalt Strike DNS 服务代码层面进行了分析，发现了检测Cobalt Strike DNS 服务的另一种方法，并选择在某大型演练活动后进行发布。

#### 0x01 Stager 分析

​		在对代码分析前，我们有必要通过抓包简单了解Cobalt Strike DNS Beacon与DNS Server的通信过程。DNS Beacon主要有两种形式。一种是带阶段下载的Stager，另一种是无阶段的Stageless。这里我们主要分析Stager Beacon，本地搭建的Cobalt Strike版本为4.2，IP地址192.168.100.101，DNS Listener绑定的域名为ns.dns.com，用到的profile配置如下:

```python
set host_stage "true";
set maxdns          "255";
set dns_max_txt     "252";
set dns_idle        "74.125.196.113"; #google.com (change this to match your campaign)
set dns_sleep       "0"; #    Force a sleep prior to each individual DNS request. (in milliseconds)
set dns_stager_prepend ".resources.123456.";
set dns_stager_subhost ".feeds.123456.";
```

​		运行Stager的Beacon后，通过WireShark可以观察到Beacon与Cobalt Strike的通信过程。捕获的数据看下图:

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteHmWa1xjiaNKjGvWty1HjR7eaDc2WjITddboK3JuR0RuXqqj9aVQAqiaQ/640?wx_fmt=png)

​		其中ns.dns.com是Cobalt Strike Listener中绑定的域名，而.feeds.123456.是我们在profile中配置的dns_stager_subhost值。整个通信的过程中Beacon请求的都是TXT记录。

​		通过nslookup请求aaa.feeds.123456.ns.dns.com的TXT记录，查看返回结果可以看到传输的数据都在text字段中，而数据开头的.resource.123456.是我们profile中dns_stager_prepend的值。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteqk6DicN7g9QEbXHGViaBMQw4FiaDETAKWI6BuQzlzBBic8WTjgJCcq3BHA/640?wx_fmt=png)

​		进一步分析后发现，Beacon请求的第一个域名是aaa.feeds.123456.ns.dns.com，然后是baa.feeds.123456.ns.dns.com，随后按照一定顺序发出大量的TXT记录查询，直到最后一个请求tkc.feeds.123456.ns.dns.com。请求顺序可以表示如下：

```c++
aaa.feeds.123456.ns.dns.com
baa.feeds.123456.ns.dns.com
           :
zaa.feeds.123456.ns.dns.com
aba.feeds.123456.ns.dns.com  
cba.feeds.123456.ns.dns.com
           :
zba.feeds.123456.ns.dns.com
aca.feeds.123456.ns.dns.com  
cca.feeds.123456.ns.dns.com
           :
zza.feeds.123456.ns.dns.com
aab.feeds.123456.ns.dns.com
cab.feeds.123456.ns.dns.com
           :
tkc.feeds.123456.ns.dns.com
```

​		不难发现，每次请求域名中的第一个子域都是固定三个字母，并按照一定顺序进行排列。排列规则看起来是包含26个字母的集合连续进行了2次笛卡尔积。所以很容易就可以模拟Stager Beacon从Cobalt Strike DNS服务请求数据。

```python
def stager():
    buff = ""
    str1 = 'abcdefghijklmnopqrstuvwxyz'
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['192.168.100.101']
    for i in product(str1, str1, str1):
        dnsc = '{0}.feeds.123456.ns.dns.com'.format(''.join(i[::-1])).strip()
        try:
            text = resolver.resolve(dnsc, 'txt')[0].to_text().strip('"')
        except NoNameservers:
            break
        except:
            return
        if text=="":
            break    
        #time.sleep(0.3)
        buff = buff + text
    return buff
```

​		查询结束后，将得到的数据进行拼接，最终数据可简单表示如下：

```c
.resources.123456.WYIIIIIIIIIIIIIIII7QZjAX...8ioYp8hnMyoYoIoAAgogoJAJAJAJAJAJAJAJAJAENFKFCEFOIAAAAAAAAFLIJNPFFIJOFIBMDPPHJAAAAPPNDGIPALFKCFGGIAEAAAAAAFHPPNAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPAAAAAAAHKDPGLIOCHPPLNKGNJINHEIMMEABKBEIKCFPBOAOAHDDPPFPKOGFBCDFFODANEJGBDANKODPGJIIIIPDDCODOGNCBLCMHHMPCEBNBMJKCF...AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
```

​		由于数据并不直观，所以还需要逆向Cobal Strike的jar包源代码还原数据处理的过程。在使用Idea反编译后，可以直接定位到加密的入口是在beacon\beaconDns.java中的setPayloadStage()函数，而传入的数据var1则是DNS Beacon的Shellcode，也就是Stager Beacon请求的最终数据。

```java
public void setPayloadStage(byte[] var1) {
    this.stage = this.c2profile.getString(".dns_stager_prepend") + ArtifactUtils.AlphaEncode(var1);
}
```

​		setPayloadStage()函数首先获取的是profile中dns_stager_prepend值，也就是.resource.123456.，然后调用了AlphaEncode()函数加密Shellcode并与前面获取的值拼接。

​		跟进AlphaEncode()函数发现其位于common\BaseArtifactUtils.java

```java
public static String AlphaEncode(byte[] var0) {
    AssertUtils.Test(var0.length > 16384, "AlphaEncode used on a stager (or some other small thing)");
    return _AlphaEncode(var0);
}
​
public static String _AlphaEncode(byte[] var0) {
    String var1 = CommonUtils.bString(CommonUtils.readResource("resources/netbios.bin"));
    var1 = var1 + "gogo";
    var1 = var1 + NetBIOS.encode('A', var0);
    var1 = var1 + "aa";
    return var1;
}
```

​		可以看到，对Shellcode只是进行简单的NetBios编码，编码后再和固定字符拼接。所以我们只需将字符串aa和gogo中间部分的数据提取出来进行NetBios解码便可以得到Shellcode。

​		以上过程很容易就可以用Python实现，可以参考如下代码:

```python
import time
from dns.resolver import *
from itertools import *
​
def stager():
    buff = ""
    str1 = 'abcdefghijklmnopqrstuvwxyz'
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['192.168.100.101']
    for i in product(str1, str1, str1):
        dnsc = '{0}.feeds.123456.ns.dns.com'.format(''.join(i[::-1])).strip()
        try:
            text = resolver.resolve(dnsc, 'txt')[0].to_text().strip('"')
        except NoNameservers:
            break
        except:
            return
        if text=="":
            break    
        #time.sleep(0.3)
        buff = buff + text
        
    if "aa" in buff and "gogo" in buff:
        f = open("beacon.bin", "wb")
        f.write(bytearray(netbios_decode(buff.split('gogo')[-1].split('aa')[0])))
        f.close()
​
​
                                
def netbios_decode(netbios):
    i = iter(netbios.upper())
    try:
        return [((ord(c)-ord('A'))<<4)+((ord(next(i))-ord('A'))&0xF) for c in i]
    except:
        return ''
   
​
if __name__=="__main__":
  stager()
```

​		运行上面的Python脚本后会在脚本目录下生成beacon.bin文件，可以直接使用Beacon Parser脚本解析配置，也可以直接使用Shellcode Loader加载上线。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhyiaFaXbXOGI0vce3pvpib915Oz7EAExGqdaMwcsYDmkicnskG9ib2Ulv2XvFcI4L27bKwrPkFNhVPHlA/640?wx_fmt=png)



#### 0x02 特征分析

​		对代码进一步分析后，我们在beacon/beaconDns.java中还发现了有趣的地方。

```java
public DNSServer.Response respond_nosync(String var1, int var2) {
    StringStack var3 = new StringStack(var1.toLowerCase(), ".");
    if (var3.isEmpty()) {
        return this.idlemsg;
    } else {
    String var4 = var3.shift();
      if (var4.length() == 3 && "stage".equals(var3.peekFirst())) {//判断第二个子域是非为stage
      return this.serveStage(var4);
    } else {
      String var5;
      String var6;
      if (!"cdn".equals(var4) && !"api".equals(var4) && !"www6".equals(var4)) {
          if (!"www".equals(var4) && !"post".equals(var4)) {
              if (this.stager_subhost != null && var1.length() > 4 && var1.toLowerCase().substring(3).startsWith(this.stager_subhost)) {
                  return this.serveStage(var1.substring(0, 3));
              } else if (CommonUtils.isHexNumber(var4) && CommonUtils.isDNSBeacon(var4))                     {
                  var4 = CommonUtils.toNumberFromHex(var4, 0) + "";
                         ...
                         ...
                  
              }
          }
     }
}
```

​		Cobalt Strike服务器在处理DNS查询的时候会先对请求域名的前两个子域进行判断，比如请求的域名为aaa.bbb.ccc.com，会判断aaa的长度是不是等于3，bbb的值是不是等于stage。如果都满足就进入serveStage()函数。跟进后发现serveStage()函数也只是简单判断了stage的长度后就返回了请求对应的值。

```java
protected DNSServer.Response serveStage(String var1) {
    int var2 = CommonUtils.toTripleOffset(var1) * 255;
    if (this.stage.length() != 0 && var2 <= this.stage.length()) {
       return var2 + 255 < this.stage.length() ? DNSServer.TXT(CommonUtils.toBytes(this.stage.substring(var2, var2 + 255))) : DNSServer.TXT(CommonUtils.toBytes(this.stage.substring(var2)));
       } else {
       return DNSServer.TXT(new byte[0]);
    }
}
```

​		也就是说，当请求的域名以aaa.stage.开头时，Cobalt Strike 服务器会直接响应我们的请求，请求aaa.stage.ns.dns.com等同于请求aaa.feeds.123456.ns.dns.com。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteBWvIhCI5yb6CyHgaTqYbOTiacb87p7jqb5GDWgmO72nk9bCTI8XbB0w/640?wx_fmt=png)

 		同时，由于Cobalt Strike服务器并没判断请求的域名后缀，当我们可以直接访问Cobalt Strike DNS服务的时候，可以直接忽略DNS Listener绑定的域名直接请求数据。当然，在profile配置host_stage为true的时候，可以使用将上面的Python代码替换feeds.123456.ns.dns.com为stage.xxx，运行后依然可以下载DNS Beacon的Shellcode。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPter4zLHa93cSichqF5NYK3h4Mltlzecg5wzdWHwUXYJNnlYg8gUBCvFtw/640?wx_fmt=png)

​		当host_stage配置为false的时候，返回的结果有些不一样。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteq48By2ymAPbOcbjDuib3ZafkAAiaePC1TOTGtDmvmIthZWCkOw7fxXUw/640?wx_fmt=png)

​		可以看到，Cobalt Strike服务器没有再返回Shellcode的数据，但是对以aaa.stage.开头的域名的TXT记录查询，Cobalt Strike服务器依旧响应了TXT记录。而其它的域名则像F-Secure研究员发现的那样，返回的是A记录，并且解析的IP就是profile中dns_idle的值。

​		当请求的域名第一个子域长度不为3开头并且第二个子域不是stage的时候，Cobalt Strike服务器还会进一步判断域名的第一个子域是否为cdn、api、www6、www、post。

```java
if (var4.length() == 3 && "stage".equals(var3.peekFirst())) {
    return this.serveStage(var4);
} else {
    String var5;
    String var6;
    if (!"cdn".equals(var4) && !"api".equals(var4) && !"www6".equals(var4)) {
       if (!"www".equals(var4) && !"post".equals(var4)) {
                         ...
        } else {
                         ...
        }
     } else {//当请求域名的第一个子域是cdn、api、www6的时候
        var3 = new StringStack(var1.toLowerCase(), ".");
        var5 = var3.shift();
        var6 = var3.shift();
        var4 = CommonUtils.toNumberFromHex(var3.shift(), 0) + "";
        if (this.cache.contains(var4, var6)) {
          return this.cache.get(var4, var6);
        } else {
           SendConversation var7 = null;
           if ("cdn".equals(var5)) {
              var7 = this.conversations.getSendConversationA(var4, var5, var6);
            } else if ("api".equals(var5)) {
              var7 = this.conversations.getSendConversationTXT(var4, var5, var6);
            } else if ("www6".equals(var5)) {
              var7 = this.conversations.getSendConversationAAAA(var4, var5, var6);
            }
​
           DNSServer.Response var8 = null;
           if (!var7.started() && var2 == 16) {
              var8 = DNSServer.TXT(new byte[0]);//返回text=“”
           } else if (!var7.started()) {
               byte[] var9 = this.controller.dump(var4, 72000, 1048576);
               if (var9.length > 0) {
                  var9 = this.controller.getSymmetricCrypto().encrypt(var4, var9);
                  var8 = var7.start(var9);
               } else if (var2 == 28 && "www6".equals(var5)) {
                  var8 = DNSServer.AAAA(new byte[16]);//返回::
               } else {
                  var8 = DNSServer.A(0L);//返回0.0.0.0
               }
           } else {
              var8 = var7.next();
           }
​
           if (var7.isComplete()) {
              this.conversations.removeConversation(var4, var5, var6);
           }
​
           this.cache.add(var4, var6, var8);
           return var8;
      }
 }
```

​		当域名为cdn，www6， api作为第一个子域的时候，Cobalt Strike服务器会对不同的情况作处理。可以看到，当请求的类型是A记录的时候，Cobalt Strike服务器会返回固定的IP值为0.0.0.0。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteQ0ooZr5BWcvzQYCK6azgynAjMkwo4fqL2Xwicl6QpssMFNibzvd47KbA/640?wx_fmt=png)

​		当请求的类型是TXT记录的收获，返回的结果中text字段为空。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteIVl4A5iajLlm18T37gVMnqnNrKWo1UZHj3uSfURqJAdxreOtRzpVoGg/640?wx_fmt=png)

​		对于AAAA记录，Cobalt Strike服务器也会返回固定的地址::，只不过只能抓包看到。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhyiaFaXbXOGI0vce3pvpib915sKwD8SIiciahWuGpymTHmPc761WphAKZ8AccJyp5cdaSUc5ia9iaMqvMhQ/640?wx_fmt=png)

​		由于返回的值都是固定的，同样没有判断域名后缀，所以完全可以拿来作为检测Cobalt Strike服务器的方法。以下是以api关键字作为检测的参考代码:

```python
def checkA(host):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [host]
    try:
        #请求的xxxx.xxx最好是随机的，并多次尝试
        ip = resolver.resolve("api.xxxx.xxx", 'A')[0].to_text()
    except:
        return False
    
    if ip == "0.0.0.0":
        return True
    return False
```

​		当第一个子域为www，post的时候，处理情况又不相同，限于篇幅这里就不分析了，有兴趣的朋友可以自行研究。



#### 0x03 检 测

​		本地验证没问题后，我们将目标转移到了公网上。为了快速地筛选出潜在的并且开启了DNS Server的Cobalt Strike服务器，我们可以通过一些关键字在网络空间探测平台中获取初定的目标。

​		通过分析发现Cobalt Strike返回的A记录中除返回的IP和域名外基本上数据是固定的。从Type字段开始到Data Length字段，Cobalt Strike每次响应都会返回\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04，后面再接4个字节的IP，这里是0.0.0.0，也就是\x00\x00\x00\x00。如下图：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPteYjvdobTWADg7Ivw835RwUYnwXzxic6OeykulRNhOMNvZhqOia5FLX8Fg/640?wx_fmt=png)

​		所以利用这样的特征，在Fofa或ZoomEye上可以很容易地就能找到潜在的开启了DNS 服务的Cobalt Strike服务器。因为有不少渗透测试人员喜欢把dns_idle设置为8.8.8.8。所以我们将0.0.0.0的IP地址替换为常用的8.8.8.8也就是\x08\x08\x08\x08作为查询关键字，便可以快速地找到潜在的监听了DNS服务的Cobalt Strike服务器。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhzYTBsgLNm3XsIRgcoRGPtemo3kQltazwmEFkw8hzNYKpmr6RvFJDdhRDyVceTicFLT7Hia1W0UvvSg/640?wx_fmt=png)

​		利用Fofa API导出了IP地址后，并用脚本进行了探测，探测的部分结果如下：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhyiaFaXbXOGI0vce3pvpib915zQKdwibAw3dca539ZE3KSXka8SzNRc13U5ShrscicGh080PFRvdsA0ug/640?wx_fmt=png)

​		同时也发现了一些开启host_stage的IP，直接下载了DNS Beacon的Shellcode，下面是某IP的检测结果。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhyiaFaXbXOGI0vce3pvpib915iaF8QUXdpV5gDBTDFR3Qqdic1yAgtFLxKS4rMdSSx2tGSR7cdWAdKwhQ/640?wx_fmt=png)



#### 0x04 防 御

​    针对上面提到的特征，可以通过修改beacon/beaconDns.java中的代码，改变respond_nosync()处理请求的流程，增加判断，修改默认的返回值。可参考如下代码(***注：该代码是4.2版本的代码，不过笔者本地测过CS最低版本是3.8，最高版本是4.2，代码可能会有差异，但是可以采取同样的方式\***):



```java
public DNSServer.Response respond_nosync(String var1, int var2) {
    StringStack var3 = new StringStack(var1.toLowerCase(), ".");
    String dname = var1.toLowerCase().trim().substring(0, var1.length() - 1);
    if (var3.isEmpty()) {
       return this.idlemsg;
    } else {
       String var4 = var3.shift();
       boolean CheckDname = false;
       //增加了判断请求的类型是否为TXT同时验证了域名后缀是否为Listener配置的字符
       if (var4.length() == 3 && var2 == 16 &&  dname.substring(3).startsWith(this.stager_subhost) && dname.endsWith(this.listener.getStagerHost().toLowerCase())) {
          return this.serveStage(var4);
       } else {
          String var5;
          String var6;
          String[] dnameArray = dname.split("\\.");
          String[] dC2Array = this.listener.getCallbackHosts().split(", ");
          for (int i=0; i<dC2Array.length; i++){
             if (dC2Array[i].endsWith(dnameArray[dnameArray.length - 2] + "." + dnameArray[dnameArray.length - 1])){
                CheckDname = true;
             }
          }
          //判断请求的域名后缀是否为绑定的域名后缀
          if (!CheckDname){
             return this.idlemsg;
          }
​
          if (!"cdn".equals(var4) && !"api".equals(var4) && !"www6".equals(var4)) {
             if (!"www".equals(var4) && !"post".equals(var4)) {
                //增加了判断请求的类型是否为TXT
                if (this.stager_subhost != null && var2 == 16&& var1.length() > 4 && var1.toLowerCase().substring(3).startsWith(this.stager_subhost)) {
                     return this.serveStage(var1.substring(0, 3));
                  } else if (CommonUtils.isHexNumber(var4) && CommonUtils.isDNSBeacon(var4)) {
                     var4 = CommonUtils.toNumberFromHex(var4, 0) + "";                
                          ...
                          ...
                  }
              }
          }else {//当请求域名的第一个子域是cdn、api、www6的时候
            var3 = new StringStack(var1.toLowerCase(), ".");
            var5 = var3.shift();
            var6 = var3.shift();
            var4 = CommonUtils.toNumberFromHex(var3.shift(), 0) + "";
            if (this.cache.contains(var4, var6)) {
                return this.cache.get(var4, var6);
            } else {
               SendConversation var7 = null;
               if ("cdn".equals(var5)) {
               var7 = this.conversations.getSendConversationA(var4, var5, var6);
            } else if ("api".equals(var5)) {
               var7 = this.conversations.getSendConversationTXT(var4, var5, var6);
            } else if ("www6".equals(var5)) {
               var7 = this.conversations.getSendConversationAAAA(var4, var5, var6);
            }
​
           DNSServer.Response var8 = null;
           if (!var7.started() && var2 == 16) {
              var8 = this.idlemsg;
              //var8 = DNSServer.TXT(new byte[0]);返回text=“”
           } else if (!var7.started()) {
               byte[] var9 = this.controller.dump(var4, 72000, 1048576);
               if (var9.length > 0) {
                  var9 = this.controller.getSymmetricCrypto().encrypt(var4, var9);
                  var8 = var7.start(var9);
               } else if (var2 == 28 && "www6".equals(var5)) {
                  var8 = this.idlemsg;
                  //var8 = DNSServer.AAAA(new byte[16]);返回::
               } else {
                  var8 = this.idlemsg;
                  //var8 = DNSServer.A(0L);返回0.0.0.0
               }
           } else {
              var8 = var7.next();
           }
​
           if (var7.isComplete()) {
              this.conversations.removeConversation(var4, var5, var6);
           }
​
           this.cache.add(var4, var6, var8);
           return var8;
      }
 }
```

​		需要注意的是，上面的代码并没有修复域名请求返回的A记录IP固定为dns_idle值的特征。但是我们可以在Cobalt Strike服务器前面再部署一台正常的DNS服务，如下图，根据请求的域名进行转发，并利用Iptable设置白名单来绕过检测，这里就不详细介绍了。具体可以参考F-Secure发布的文章末尾提到的方法。

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhyiaFaXbXOGI0vce3pvpib915ibg6gBEzMBiaJq1RqqfMicjFTMAtAMXKibTDF3GAUGWAiakP61WaibhjYuRA/640?wx_fmt=png)

​    

#### 0x05 总 结

​		本篇文章简单分析了Cobalt Strike DNS Beacon与Cobalt Strike 服务之间的通信，并在分析Cobalt Strike DNS 服务的代码中找到了以下的特征：

1. 当Cobalt Strike服务器的profile配置stage_host为true的时候，可以使用带有stage关键字的域名模拟stager下载DNS Beacon的Shellcode。

2. 使用api、cdn、www6作为第一个子域的域名如api.ns.dns.com向Cobalt Strike DNS服务查询A记录时将返回固定ip地址0.0.0.0，查询TXT记录是返回的text字段为空。

3. 当查询时用目标Cobalt Strike的作为名称解析服务器的时候，上述请求可以忽略域名后缀，比如查询api.xxx.xxxx和查询api.ns.dns.com都会返回0.0.0.0。

   ​	结合以上特征，可以精确地检测出监听了DNS的Cobalt Strike服务器，并在公网上得到了验证，同时也给出了防御的参考代码和思路。

**参考链接：**

​		https://labs.f-secure.com/blog/detecting-exposed-cobalt-strike-dns-redirectors/



​       																								**扫码关注公众号：非攻安全**

![](https://mmbiz.qpic.cn/mmbiz_jpg/ibXzNXqPKUhwkMZicfsXwZf7506dGaC5pTJ8GAqUZSRbzaBWHm4sOZITciapRUibfWYC0Q9NqnZMicRDY6BxfpbHbfg/0?wx_fmt=jpeg)
