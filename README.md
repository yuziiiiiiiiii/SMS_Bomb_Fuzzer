<h1 align="center">SMS_Bomb_Fuzzer - 短信轰炸 Bypass</h1>

>* Burp suite 短信轰炸辅助绕过插件，内置多种绕过和变形方法
>* 默认使用jdk1.8编译

**郑重声明：文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，<u>任何人不得将其用于非法用途以及盈利等目的，否则后果自负</u>** 
<p align="center">
<a href="https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer"><img src="https://img.shields.io/badge/Burp%20Suite-Extension-orange"></a>
<a href="https://github.com/yuziiiiiiiiii/SMS_Bomb_Fuzzer"><img  src="https://goreportcard.com/badge/github.com/projectdiscovery/httpx"></a>
</p>
<p align="center"><a href="#插件功能">插件功能</a> · <a href="#插件描述">插件描述</a> · <a href="#安装使用">安装使用</a> · <a href="#技术交流">技术交流</a></p>

---

## 插件功能

本Burp Suite插件专为短信轰炸漏洞检测设计，提供自动化Fuzz测试！

<img width="3167" height="1305" alt="PixPin_2026-05-25_21-06-01" src="https://github.com/user-attachments/assets/8e463a70-3670-41e4-98a8-92b998666afa" />


🛡️ 绕过手段包含但不限于以下：

* 参数污染
* 参数复用
* 参数编码
* 垃圾字符
* 特殊字符
* 号码区号
* 接口遍历
* 组合测试
* XFF伪造
* ......

## 插件描述

### 2026-05-25更新
#### SMS Bomb Fuzzer V4.0
- 新增选择性测试FUZZ模式，用户可以自行选择需要的测试CASE进行FUZZ

<img width="1476" height="917" alt="PixPin_2026-05-25_21-05-06" src="https://github.com/user-attachments/assets/5574cec2-3237-4dd3-90a7-9fb48d7b8e71" />

- 测试列表中无用数据可以进行删除

- 优化UI和部分处理逻辑，体验更佳！

**********

### 2026-05-25更新
#### SMS Bomb Fuzzer V3.2
- 修复请求包中JSON嵌套数据的丢失问题

**********

### 2025-06-15更新
#### SMS Bomb Fuzzer V3.1
- 优化线程、UI和部分处理逻辑，体验更佳！

- 新增对已测试的数据包进行排序功能，方便筛选！

![](https://github.com/user-attachments/assets/3b60218f-6344-4638-94a3-fabfec9bdcca)

**********

### 2025-04-25更新
#### SMS Bomb Fuzzer V3.0
* 新增停止按钮，可以随时停止正在测试中的项目，防封！

![](https://github.com/user-attachments/assets/572ea117-caa7-46b2-b949-043f9ab4f6e2)

* 新增参数自定义FUZZ功能，每当`Send to SMS Bomb Fuzzer`后会弹出选择参数窗口

![](https://github.com/user-attachments/assets/b25a6734-07da-4707-81cd-9a18d1479ee6)

**********

### 2025-03-16更新
#### SMS Bomb Fuzzer V2.1
* 增加对number包含`*`或`+86`等情况的支持，覆盖更多场景！

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250316012811196.webp)

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250316012843443.webp)

* 增加了更多的绕过和变形手法（如有未涉及的绕过和变形，欢迎提交issues！）

**********

### 2025-03-11更新
#### SMS Bomb Fuzzer V2.0
* 增加`GET`请求中路径的检测和测试，覆盖更多场景！

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250311235707242.webp)

* 增加了更多的绕过和变形手法（如有未涉及的绕过和变形，欢迎提交issues！）

**********

* 支持`Json`格式。
* 支持自定义 `number` 用于测试接收。
* 支持 `GET、POST、JSON、Cookie` 请求中的参数测试。
* 支持手动开启或关闭`短信接口测试`和`组合测试`选项（开启后会发送大量测试paylaod）
* 支持`白名单`功能

## 安装使用

1. 下载`Releases`中的`SMS_Bomb_Fuzzer.jar`，然后将jar文件导入BurpSuite

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250307012034724.webp)

2. 点击"Next"，导入成功

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250308003410006.webp)

3. 将`用于发送短信的数据包`右键请求内容 → "Extensions" → "SMS Bomb Fuzzer" → "Send to SMS Bomb Fuzzer"

![4](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250307014434369.webp)

4. 开始测试并分析响应（测试完成状态会变化）

![](https://gitee.com/yuziiiiiiiiii/blog/raw/master/img/20250307005532861.webp)

## 技术交流

![qr-SMS_Bomb_Fuzzer-2025-04-24_16-55-54-880](https://github.com/user-attachments/assets/188e66a4-3ba2-4816-b0d2-d353832e3c35)
