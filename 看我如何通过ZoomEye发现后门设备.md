### 看我如何通过ZoomEye发现后门设备

​		去年研究IOT设备漏洞的时候，我们发现RCE类型的漏洞大多是无直接回显的，通常会使用OOB带外或反弹的方式回显数据。实际上，很多IOT设备都会自带telnetd服务，可以在目标设备上执行命令iptables -F && telnetd -p 8080 -l /bin/sh监听端口8080，然后使用telnet连接目标8080端口，就得到一个正向的Shell。

​		那么公网上会不会有直接这样利用而留下的后门呢？我们很快就在ZoomEye上得到了验证。

#### **0x01 分析**

​		类似于ZoomEye这种网络空间探测平台，其在扫描公网IP的时候都会有端口扫描，协议探测的过程。而在协议探测时，扫描探头一般都是向目标发送特定协议数据，然后根据返回的结果是否达到预期来判断协议类型并保存返回的结果。

​		而上面使用telnetd创建的正向Shell由于不需要认证，被扫描时会把探头的数据直接交给/bin/sh处理，所以会返回类似下面语法错误的信息。

```shell
\xff\xfd\x01\xff\xfd\x1f\xff\xfd!\xff\xfb\x01\xff\xfb\x03


/ # GET / HTTP/1.0
/bin/sh: GET: not found
/ # 
/ #
```

​		有的甚至会返回特定的banner信息。

```shell
\xff\xfd\x01\xff\xfd\x1f\xff\xfb\x01\xff\xfb\x03


BusyBox v1.27.2 (2019-04-01 19:16:06 CST) built-in shell (ash)
Enter \'help\' for a list of built-in commands.

/fhrom/fhshell # <?xml version="1.0" ?><methodCall><methodName>nmap.probe</metho
dName></methodCall>
/bin/sh: syntax error: unexpected redirection
/fhrom/fhshell #
```

#### **0x02 探索**

​		针对以上的返回信息，我们提取了部分关键字如"busybox"、"help"、 "/bin/sh"、"syntax error"、"shell"在ZoomEye上搜索。果然搜索到了大量存在问题的IP。如下ZoomEye显示有30000多条：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CYBMxuaIjHrhTYwB4iaics3ILnBfS8sibnZ5pCdThojhTWhdHOS7jtlKww/640?wx_fmt=png)

​		然后找了个IP用telnet连接上去，果然可以执行命令：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CUBFJEr89GEibrCdZAxGQN6p53abJkuEJCozQxJicz3DWnmgDwjntibHRA/640?wx_fmt=png)

​		用ZoomEye查看了开放的端口。发现开了8080端口的web服务，并且关联了漏洞和CVE编号如下：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CQvHsO1L9qQ7ibtBDbuuCBicRRL6G9znMAJlxZy6BPXl9EVBDQMKrurhw/640?wx_fmt=png)

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CThsSLsCY1j5JzF8MPYwKyMCVcNPfpmeJptxKLNXicWMKQnicSFeyceJA/640?wx_fmt=png)

​		访问其WEB服务后发现是一台Tp-link的路由器设备：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CxUwSib4C8oQWibkmcp2a1UXlUoictDYic7oajCnxwKAwlyBn9c9uCdTbiaQ/640?wx_fmt=png)

​		随后对更多IP进行了分析，发现基本上都是些IOT设备，包括路由器，VPN防火墙，光猫、摄像头等，几乎都开启了web服务，也都爆过严重的rce漏洞，所以猜测是被攻击后留下的后门。涉及的设备厂商包括Cisco、Netgear、D-link、Tp-link和Asus等，当然也有不少蜜罐混在其中。![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CnPlicbNlwEziam2uD3ibzFPClAvSyCeCHMjh8uHFWMZMraYc6EwqWC0AA/640?wx_fmt=png)

#### **0x03 惊喜**

​		通过不断的变换关键字搜索，发现了更多被攻击的目标。同时也遇到了不少设备并没发现公开可利用的漏洞，但是却存在问题。

如下图所示的IP，仅仅开放了telnet端口，没有开启web服务。![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CQp6ibQYHTiaqx7TjPsfK0PyHV8gmMBPxmqUbl4AjFkFkOgEoyBCZNS8w/640?wx_fmt=png)

​		随后根据23端口的一些信息，最终确认了是某火的一个接入层IP RAN产品，通常是运营商使用。不过看起来并不像是被攻击后留下的，怀疑是运营商调试用的，存在未授权访问。那这算是0day吗？

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CSzEx3suHQc2DqMBsfiaBW6fvx9xaRDnPorZNVQoib73Dj3tYwbxF7Hcg/640?wx_fmt=png)

​		同时还发现了类似于下图这样的：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3CJ5RibTh6LWzC2BcA5oCEyWN0IGjHPbntNGCW7UFL76c42z5krN31yNQ/640?wx_fmt=png)

​		不乏还有这样的：

![img](https://mmbiz.qpic.cn/mmbiz_png/ibXzNXqPKUhwtR1dGd2icC4LIdzxb9Ic3ChPWW1xwuu4k26BAGOTdUKnlUiaSLkVnicO35FUiaL25EKCGJGp9uBGGzQ/640?wx_fmt=png)

​		看着这熟悉的报错，指不定就可以通过ZoomEye在线挖0day了，有兴趣的可以自行研究。

#### **0x04 总结**

本篇文章主要介绍了如何通过网络空间搜索引擎以ZoomEye为例发现并识别公网上被漏洞利用过或者存在后门的设备。藉此希望IOT厂商也应该跟踪设备的安全问题和更新补丁，同时企业也应该关注漏洞修复和公网相应资产的收敛情况。

​                                                                                            **扫码关注公众号：非攻安全**

![](https://mmbiz.qpic.cn/mmbiz_jpg/ibXzNXqPKUhwkMZicfsXwZf7506dGaC5pTJ8GAqUZSRbzaBWHm4sOZITciapRUibfWYC0Q9NqnZMicRDY6BxfpbHbfg/0?wx_fmt=jpeg)
