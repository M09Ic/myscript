# Author: M09Ic

import requests
import re
import time
from functools import reduce
import sqlite3
import IPy
import getopt,sys
from lxml import etree
import whois
import os
from math import ceil

requests.packages.urllib3.disable_warnings()


def time2stamp(date):
    # like ""2019-05-05 20:00:00""
    timeArray = time.strptime(date, "%Y-%m-%d %H:%M:%S")
    timestamp = int(time.mktime(timeArray))
    return timestamp


def stamp2time(timestamp):
    time_local = time.localtime(timestamp)
    date = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
    return date


# 获取token
def get_tokenId(session, url="https://ip/login"):
    r = session.get(url, verify=False)
    restr = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
    tokenId = re.findall(restr, r.text)[0]
    return tokenId


# 流量分析平台登录
def login_liuliang(session):
    url = "https://ip/user/login"
    tokenId = get_tokenId(session)
    username = "admin"
    pa = "*****"
    data = {"userAccount": username, "userPassword": pa, "tokenId": tokenId}
    r = session.post(url, data=data, verify=False)
    return r


# apt平台登录
def login_apt(session):
    url = "https://ip/admin/j_spring_security_check"
    tokenId = get_tokenId(session, "https://ip/admin/login")
    username = "admin"
    pa = "*****"
    data = {"j_username": username, "j_password": pa, "tokenId": tokenId}
    r = session.post(url, data=data, verify=False)
    return r


def ip_into_int(ip):
    # 先把 192.168.1.13 变成16进制的 c0.a8.01.0d ，再去了“.”后转成10进制的 3232235789 即可。
    # (((((192 * 256) + 168) * 256) + 1) * 256) + 13
    return reduce(lambda x, y: (x << 8) + y, map(int, ip.split('.')))


# 判断是否是内网ip
def is_internal_ip(ip):
    ip = ip_into_int(ip)
    net_a = ip_into_int('10.255.255.255') >> 24
    net_b = ip_into_int('172.31.255.255') >> 20
    net_c = ip_into_int('192.168.255.255') >> 16
    return ip >> 24 == net_a or ip >> 20 == net_b or ip >> 16 == net_c

# 更新白名单
def update_whitelist():
    db = Db()
    db.create_whitelist()
    for i in open('whitelist.txt', 'r'):
        db.insert_white(i.strip(), 'Yundun')

# TODO
def get_whois(db,h):
    f = open('whois.txt', 'w')
    url = "http://s.tool.chinaz.com/same"
    if h == 0:
        ips = db.query_ip('taishi')
    else:
        ips = db.query_ip('taishi',stamp2time(time.time()-60*60*h),stamp2time(time.time()))
    for ip in ips:

        param = {"s": ip}
        r = requests.get(url, params=param)
        tree = etree.HTML(r.text)
        li = tree.xpath('//ul[@class="ResultListWrap"]/li[contains(@class,"ReLists")]')

        for i in li:
            uname = i.xpath('./div[2]/a/text()')[0]
            title = get_title(uname)

            try:
                print("[+] 获取whois信息成功: " + '%s --- %s:%s' % (ip, uname, title))
                f.writelines('%s --- %s:%s' % (ip, uname, title) + '\n')
                f.writelines(whois.whois(uname) + '\n')

            except:
                f.writelines("no whois info! \n")
            f.writelines('-' * 50 + '\n')
    f.close()
    return 1


def get_title(uname):
    url = "http://s.tool.chinaz.com/ajaxsync.aspx"
    param = {'at': 'title', 'url': uname}
    try:
        r = requests.post(url, params=param, timeout=3)
        return r.text
    except:
        return '--'
# 安恒apt与全流量分析用的同一套接口,只是参数名字不同
class getData:
    def __init__(self):
        self.url = "https://ip/events/queries"
        self.session = requests.session()
        # login_liuliang(self.session)
        login_apt(self.session)
        self.tokenId = get_tokenId(self.session, self.url)

    # 获取queryid 默认查询近一小时内数据
    def action_add(self, lon='M5'):

        param = {"action": "add", "format": "json", "timeAgo": lon, "queries": "cmb=1", "token": self.tokenId}

        r = self.session.post(self.url, params=param)
        rJson = r.json()

        if "update success" == rJson['desc']:
            return (r.json()['detail']['id'])
        else:
            return 0

    # 获取id
    def action_execute(self, queryid):
        param = {"action": "execute", "format": "json", "id": queryid, "token": self.tokenId}
        r = self.session.post(self.url, params=param)

        rJson = r.json()
        if "update success" in rJson['desc']:
            return (rJson['id'])
        else:
            return 0

    # 获取简报
    def action_id(self, queryid):
        param = {"format": "json", "id": queryid, "token": self.tokenId}
        r = self.session.get(self.url, params=param)
        rJson = r.json()
        if "update success" in rJson['desc']:
            return (rJson['detail']['matchnum'])
        else:
            return 0

    # 获取详细信息
    def action_paginate(self, queryid, id, limit, start=0):
        param = {"action": "paginate", "format": "json", "queryid": queryid, "id": id, "token": self.tokenId}
        data = {"start": 0, "limit": limit}
        r = self.session.post("https://ip/events", params=param, data=data, timeout=100)
        rJson = r.json()
        if "update success" in rJson['desc']:
            # return rJson
            return (rJson['list'])
        else:
            return 0

    def run(self, lon='M5'):
        queryid = self.action_add(lon)
        id = self.action_execute(queryid)
        matchnum = self.action_id(queryid)
        print("最近五分钟共%d次威胁报告" % matchnum)
        return (self.action_paginate(queryid, id, matchnum))

# 数据库操作
class Db:
    def __init__(self):
        self.conn = sqlite3.connect("data.db")
        self.c = self.conn.cursor()

    # 创建黑名单表
    def create_blacklist(self):
        try:
            self.c.execute('''
            CREATE TABLE blacklist(
            ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE ,
            eventID INTEGER NOT NULL UNIQUE ,
            SIP VARCHAR(15) ,
            DIP VARCHAR(15) ,
            Atime  datetime default(datetime('now', 'localtime')) ,
            Atype TEXT
            )
            ''')
            return 1
        except:
            return 0

    # 态势
    def create_taishi(self):
        try:
            self.c.execute('''
            CREATE TABLE taishi(
            ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE ,
            eventID VARCHAR(30) NOT NULL UNIQUE ,
            SIP VARCHAR(15) ,
            DIP VARCHAR(15) ,
            Longitude VARCHAR(30),
            Latitude VARCHAR(30),
            GeoAddress VARCHAR(100),
            Atime  datetime default(datetime('now', 'localtime')) ,
            Atype TEXT
            )
            ''')
            return 1
        except:
            return 0


    # 创建白名单表
    def create_whitelist(self):
        try:
            self.c.execute('''
                CREATE TABLE whitelist(
                ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE ,
                IP VARCHAR(20) NOT NULL UNIQUE ,
                des TEXT
            )
            ''')
            return 1
        except:
            return 0


    def create_logs(self):
        try:
            self.c.execute('''
            CREATE TABLE logs(
            ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE ,
            eventID VARCHAR(30) NOT NULL UNIQUE ,
            SIP VARCHAR(15) ,
            DIP VARCHAR(15) ,
            status INTEGER,
            option VARCHAR(10),
            url TEXT ,
            postdata  TEXT, 
            Atime  datetime default(datetime('now', 'localtime')) 
            )
            ''')
            return 1
        except:
            return 0
    def create_weakpass(self):
        try:
            self.c.execute('''CREATE TABLE weakpass(
            ID INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL UNIQUE ,
            eventID  VARCHAR(30) NOT NULL UNIQUE ,
            SIP VARCHAR(15) ,
            DIP  VARCHAR(15) ,
            service VARCHAR(50),
            user VARCHAR(50) ,
            pass VARCHAR(50),
            Atime  datetime default(datetime('now', 'localtime'))
            )
            ''')
        except:
            return 0

    # 插入白名单数据
    def insert_white(self, IP, des):
        sql = "INSERT OR IGNORE INTO  whitelist (IP,des) VALUES ('%s','%s')" % (IP, des)
        print(sql)
        self.c.execute(sql)

        return 1

    def insert_taishi(self,eventID, SIP, DIP, Longitude,Latitude,GeoAddress, Atime, Atype):
        sql = "INSERT OR IGNORE INTO  taishi (eventID,SIP,DIP,Longitude,Latitude,GeoAddress,Atime,Atype) VALUES ('%s','%s','%s','%s','%s','%s','%s','%s')" % (eventID, SIP, DIP, Longitude,Latitude,GeoAddress,Atime, Atype)
        print("[+] 获取态势感知数据%s,源ip:%s,目的ip:%s,事件: %s,时间: %s"%(eventID, SIP, DIP, Atime, Atype))
        self.c.execute(sql)

        return 1

    def insert_logs(self,eventID, SIP, DIP,status,option,uri ,port,postdata ,Atime):
        sql = "INSERT OR IGNORE INTO  logs (eventID,SIP,DIP,status,option,url,postdata,Atime) VALUES ('%s','%s','%s',%s,'%s','%s','%s','%s') "%(eventID, SIP, DIP,status,option,DIP+':'+port+uri ,postdata,Atime)

        # print("态势感知日志id:%s,来源ip:%15s,%s %s %s:%s%s ,时间:%s" % (eventID, SIP,status,option,DIP,port,uri, Atime))
        self.c.execute(sql)

        return 1


    # 插入黑名单数据
    def insert(self, eventID, SIP, DIP, Longitude,Latitude,Atime, Atype):
        sql = "INSERT OR IGNORE INTO  blacklist (eventID,SIP,DIP,Longitude,Latitude,Atime,Atype) VALUES ('%s','%s','%s','%s','%s','%s','%s')" % (eventID, SIP, DIP, Longitude,Latitude, Atime, Atype)
        print(sql)
        self.c.execute(sql)

        return 1

    # 插入弱密码名单
    def insert_weakpass(self, eventId,SIP, DIP, service, user, password, Atime):
        sql = "INSERT OR IGNORE INTO  weakpass (eventID,SIP,DIP,service,user,pass,Atime) VALUES ('%s','%s','%s','%s','%s','%s','%s')" % (eventId,
        SIP, DIP, service, user, password, Atime)
        print("[+] 发现%s服务存在弱密码账号%s,密码为:%s" % (service, user, password))
        self.c.execute(sql)

        return 1


    # 查询全部黑名单数据
    def query_all(self,table):
        data = self.c.execute("SELECT * FROM %s"%table)
        return data

    # 查询黑名单ip,返回list
    def query_ip(self,table,start = '0',end = stamp2time(time.time())):
        list = []
        if start == '0' :
            data = self.c.execute("SELECT sip FROM %s GROUP BY sip"%table)
        else :
            # print("SELECT sip FROM %s WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')  GROUP BY sip " %(table,start,end))
            data = self.c.execute("SELECT sip FROM %s WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')  GROUP BY sip " %(table,start,end))
        for i in data:
            list.append(i[0])
        return list


    def query_geo(self,start = '0',end = stamp2time(time.time())):
        list = []
        if start == '0' :
            data = self.c.execute("SELECT sip,Longitude,Latitude,GeoAddress FROM taishi GROUP BY sip")
        else :
            # print("SELECT sip FROM %s WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')  GROUP BY sip " %(table,start,end))
            data = self.c.execute("SELECT sip,Longitude,Latitude,GeoAddress FROM taishi WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')  GROUP BY sip " %(start,end))
        for i in data:
            list.append(i)
        return list

    def query_eventid(self,table):
        list = []
        data = self.c.execute("SELECT eventID FROM %s "%table)
        for i in data:
            list.append(i[0])
        return list

    def query_wearkpass(self,start = '0',end = stamp2time(time.time())):
        list = []
        if start == '0' :

            data = self.c.execute("SELECT * FROM weakpass ")
        else:
            data = self.c.execute("SELECT * FROM weakpass WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')"%(start,end))
        for i in data :
            list.append(i)
        return list

    # 自定义查询语句
    def query(self, sql):
        data = self.c.execute(sql)
        return data

    def query_logip(self,start = '0',end = stamp2time(time.time())):
        l = []
        if start == '0' :
            data = self.c.execute("SELECT SIP FROM logs GROUP BY SIP" )
        else :
            data = self.c.execute("SELECT SIP FROM logs WHERE datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s') GROUP BY SIP"%(start,end) )
        for i in data:
            l.append(i)
        return  list(set(l))

    def query_log(self,ip,start = '0',end = stamp2time(time.time())):
        list = []
        if start == '0' :
            data = self.c.execute("SELECT DIP,Atime,option,url,status,postdata FROM logs WHERE SIP = '%s'"%ip )
        else:
            data = self.c.execute("SELECT DIP,Atime,option,url,status,postdata FROM logs WHERE SIP = '%s' AND datetime(Atime) > datetime('%s') AND datetime(Atime) < datetime('%s')"%(ip,start,end))
        for i in data:
            list.append(i)
        return  list

    def create(self):
        # self.create_blacklist()
        self.create_whitelist()
        self.create_taishi()
        self.create_weakpass()
        self.create_logs()
        self.conn.commit()
        print('[*] Create table success!')


    def commit(self):
        self.conn.commit()
        
    def close(self):

        self.conn.commit()
        print('[*] Commit data success!')
        self.c.close()

# 判断ip是否在白名单中
def is_white(IP):
    db = Db()
    data = db.query_ip('whitelist')
    for i in data:
        if (IP == i or IP in IPy.IP(i)):
            return True

    return False


# 态势感知平台模拟登录有点问题,目前只能手动填cookie,获取数据是没问题
class Taishi:
    # TODO
    def __init__(self):
        self.url = "https://ip"
        self.user = "******"
        self.password = "**********************************"
        self.session = requests.session()

        # 登录
        url = self.url + '/api/login'
        header = {'Referer':'https://ip/index.html','Content-Type':'application/x-www-form-urlencoded'}
        data = {'username':self.user,'password':self.password,}
        self.session.get(self.url + '/index.html',verify=False)
        self.session.post(url,data=data,headers=header, verify=False)


    # 获取数据,成功则返回数据字典,失败返回{'data':0}
    def getlist(self,h):
        url = self.url + "/api/search/alarms/getList"
        header = {"Content-Type": "application/json", "Referer": "https://ip/index.html",
                  "Accept-Language": "zh-CN,zh;q=0.9"}
        data = {"endTime": stamp2time(time.time()), "startTime": stamp2time(time.time()-60*60*h), "from": 0, "size": 9999, "searchTypeNum": 3,"userName": "admin"}

        r = self.session.post(url, json=data, headers=header, verify=False)
        rJson = r.json()

        if rJson['code'] == 0:
            return rJson['data']
        else :
            return {'data':0}

    def getsize(self,h,ip):
        url =self.url +"/api/search/logs/total"
        header = {"Content-Type": "application/json", "Referer": "https://ip/index.html",
                  "Accept-Language": "zh-CN,zh;q=0.9"}
        data = {"endTime":stamp2time(time.time()),"startTime":stamp2time(time.time()-60*60*h),"searchTypeNum":1,"indexJson":{"log":0,"flowaudit":1,"flowsession":0},"queryStr":"","extraUi":{"srcAddress":ip,"direction":"10"}}


        r = self.session.post(url, json=data , headers=header, verify=False)
        return r.json()['data']

    def gethttp(self,h,ip):
        url = self.url + "/api/search/logs/getList"

        header = {"Content-Type": "application/json", "Referer": "https://ip/index.html",
                  "Accept-Language": "zh-CN,zh;q=0.9"}
        # stamp2time(time.time()-60*h)
        print("[+] 最近%d小时%s共有%d条访问记录"%(h,ip,self.getsize(h,ip)))

            # data = {"endTime": stamp2time(time.time()),"startTime":stamp2time(time.time()-60*60*h),"from":0,"size":9999,"interval":"榛樿","searchTypeNum":1,"indexJson":{"log":0,"flowaudit":1,"flowsession":0},"queryStr":"","condition":{"str":{},"num":{},"strNot":{},"numNot":{}},"extraUi":{"productVendorName":"","srcSecurityZone":"","srcAddress":"","srcPort":"","srcUserName":"","direction":"10","destSecurityZone":"","destAddress":"","destPort":"","destHostName":"","requestUrl":""},"userName":"admin"}
        data = {"endTime": stamp2time(time.time()),"startTime":stamp2time(time.time()-60*60*h),"from":0,"size":9999,"searchTypeNum":1,"indexJson":{"log":0,"flowaudit":1,"flowsession":0},"condition":{"str":{},"num":{},"strNot":{},"numNot":{}},"extraUi":{"srcAddress":ip,"direction":"10"},"userName":"admin"}

        r = self.session.post(url, json=data, headers=header, verify=False)

        rJson = r.json()

        if rJson['code'] == 0:
            return rJson['data']



# 获取apt数据并填入数据库
def get_apt(db,lon='M5'):
    getdata = getData()
    data = getdata.run(lon)
    blackeventId = db.query_eventid('blacklist')

    for i in data:

        if (is_internal_ip(i['sip']) == False and is_white(i['sip']) == False and (
                int(i['id']) not in blackeventId) and (i['type'] != "弱口令")):
            db.insert(i['id'],i['sip'],i['dip'],i['happentime'],"%s : %s"%(i['type'],i['signame']))
        elif (i['type'] == "弱口令"):
            db.insert_weakpass(i['sip'], i['dip'], i['payload'].split(':')[0].replace("账户", ''), i['loginuser'],
                               i['message'], i['happentime'])


# 获取态势感知数据,填入数据库
def get_taishi(db,h):
    taishi = Taishi()
    data = taishi.getlist(h)['data']
    if data == 0 :
        return 0
    eventid = db.query_eventid('weakpass')
    ip = []
    for i in data:
        if (i['事件名称(name)'] != '弱口令') and (is_internal_ip(i['来源IP(srcAddress)']) == False ) and i['事件ID(eventId)'] not in eventid :
            try:
                srcGeoLongitude = i['来源经度(srcGeoLongitude)']
                srcGeoLatitude = i['来源纬度(srcGeoLatitude)']
                srcGeoAddress = i['来源地理详细地址(srcGeoAddress)']
                db.insert_taishi(i['事件ID(eventId)'],i['来源IP(srcAddress)'],i['目的IP(destAddress)'],srcGeoLongitude,srcGeoLatitude,srcGeoAddress,i['采集器接收时间(collectorReceiptTime)'],i['事件名称(name)'])

            except:
                db.insert_taishi(i['事件ID(eventId)'], i['来源IP(srcAddress)'], i['目的IP(destAddress)'], '','','', i['采集器接收时间(collectorReceiptTime)'], i['事件名称(name)'])
            ip.append(i['来源IP(srcAddress)'])
        elif (i['事件名称(name)'] == '弱口令') and (i['事件ID(eventId)'] not in eventid):
            db.insert_weakpass(i['事件ID(eventId)'],i['来源IP(srcAddress)'], i['目的IP(destAddress)'], i['应用协议(appProtocol)'], i['来源用户名(srcUserName)'],i['密码(passwd)'], i['采集器接收时间(collectorReceiptTime)'])
    return list(set(ip))


def get_log(db,h,ip=()):
    taishi = Taishi()
    for j in ip:
        data = taishi.gethttp(h,j)['data']
        if data == 0 :
            return 0
        f = open('./logs/%s.txt'%j,'w')
        eventid = db.query_eventid('logs')
        for i in data:
            if i['事件ID(eventId)'] not in eventid:

                try:
                    body = i['请求Body(requestBody)'].strip().replace("'", "''")

                except:
                    body = ''
                if i['请求方法(requestMethod)'] == 'GET' or i['请求方法(requestMethod)'] == 'HEAD':

                    #print("[+] 态势感知日志id:%s,来源ip:%15s,%s %s %s:%s%s"%(i['事件ID(eventId)'],i['来源IP(srcAddress)'],i['请求响应码(responseCode)'],i['请求方法(requestMethod)'],i['目的IP(destAddress)'],i['目的端口(destPort)'],i['URI(requestUrlQuery)']))
                    db.insert_logs(i['事件ID(eventId)'],i['来源IP(srcAddress)'],i['目的IP(destAddress)'],i['请求响应码(responseCode)'],i['请求方法(requestMethod)'],i['URI(requestUrlQuery)'].replace("'","''"),i['目的端口(destPort)'],'',i['采集器接收时间(collectorReceiptTime)'])
                    if ip != '':
                        f.writelines('%s - [%s] "%s %s HTTP/1.1" %s \n '%(i['目的IP(destAddress)'],i['采集器接收时间(collectorReceiptTime)'],i['请求方法(requestMethod)'],i['URI(requestUrlQuery)'],i['请求响应码(responseCode)']))

                elif i['请求方法(requestMethod)'] == 'POST':

                    #print("[+] 态势感知日志id:%s,来源ip:%15s,%s %s %s:%s%s ,postdata:%s" % (i['事件ID(eventId)'], i['来源IP(srcAddress)'], i['请求响应码(responseCode)'], i['请求方法(requestMethod)'],i['目的IP(destAddress)'], i['目的端口(destPort)'], i['URI(requestUrlQuery)'],body))
                    db.insert_logs(i['事件ID(eventId)'], i['来源IP(srcAddress)'], i['目的IP(destAddress)'], i['请求响应码(responseCode)'],i['请求方法(requestMethod)'], i['URI(requestUrlQuery)'].replace("'", "''"), i['目的端口(destPort)'],body, i['采集器接收时间(collectorReceiptTime)'])
                    if ip != '':
                        try:
                            f.writelines('%s - [%s] "%s %s HTTP/1.1" %s - %s \n'%(i['目的IP(destAddress)'],i['采集器接收时间(collectorReceiptTime)'],i['请求方法(requestMethod)'],i['URI(requestUrlQuery)'],i['请求响应码(responseCode)'],body))
                        except:
                            pass


        f.close()
    return  1

def export2geo(db,h):

    start = stamp2time(time.time() - 60 * 60 * h)
    end = stamp2time(time.time())
    if h == 0 :
        print('[*] 导出全部攻击者地理位置  ')
        geo = db.query_geo()
    else :
        print('[*] 导出攻击者地理位置 ,时间: ' + stamp2time(time.time() - 60 * 60 * h) + ' --- ' + stamp2time(time.time()))
        geo = db.query_geo(start,end)
    f = open('geo.csv','w')
    for i in geo :
        l=''
        for j in i :
            l += j +','
        print('[+] 地理位置:'+l)
        f.writelines(l+'\n')
    f.close()



def export2log(db,h):
    ips = db.query_ip('logs')
    sum = 0
    if h == 0:
        print('[*] 导出全部攻击http日志 ')
    else:
        print('[*] 导出攻击http日志 ,时间: ' + stamp2time(time.time() - 60 * 60 * h) + ' --- ' + stamp2time(time.time()))

    for ip in ips:
        f = open('./logs/%s.txt'%ip,'w')
        if h == 0:

            data = db.query_log(ip)
        else:
            data = db.query_log(ip,stamp2time(time.time()-60*60*h),stamp2time(time.time()))
        num = 0
        for i in data:
            try:
                f.writelines('%s - [%s] "%s %s HTTP/1.1" %s - %s \n'%i)
                num += 1
            except:
                pass
        sum += num
        print("[+] 导出ip:%s最近%d小时攻击日志,共%d条"%(ip,h,num))
        f.close()

    print('[*] 成功导出最近%d小时的攻击日志,期间共%s个ip尝试攻击共%s次'%(h,len(ips),sum))

# 导出黑名单,flag =1为导出单个ip,flag = 2为导出C段
def export2blackip(db,h):


    if h == 0 :
        print('[*] 导出全部ip黑名单')
        data = db.query_ip('taishi')
    else :
        print('[*] 导出ip黑名单 ,时间: ' + stamp2time(time.time() - 60 * 60 * h) + ' --- ' + stamp2time(time.time()))
        data = db.query_ip('taishi',stamp2time(time.time()-60*60*h),stamp2time(time.time()))
    data = list(set(data))
    f = open("banip.txt", 'w')
    for i in data:
            f.writelines(i + '\n')
    print('[*] 已导出ip黑名单至当前目录banip.txt')
    f.close()

# 将收集到的弱密码保存到文本
def weakpass2txt(db,h):

    if h == 0 :
        print('[*] 导出全部弱密码绵羊墙 ,时间: '  + stamp2time(time.time()-60*60*h) + ' --- ' + stamp2time(time.time()))
        data = db.query_wearkpass()
    else :
        print('[*] 导出弱密码绵羊墙 ,时间: '  + stamp2time(time.time()-60*60*h) + ' --- ' + stamp2time(time.time()))
        data = db.query_wearkpass( stamp2time(time.time()-60*60*h),stamp2time(time.time()) )
    f = open('sheepwall.txt', 'w')
    for i in data:

        print("[+] service: %s ,user: %s,pass: %s"%(i[3],i[4],i[5])+'\n')
        f.writelines("service: %s ,user : %s,pass : %s"%(i[3],i[4],i[5])+'\n')
    f.close()
    return 0


def run(db,h):
    num = 0
    db.create()
    while True:
        num += 1
        start = stamp2time(time.time() - 60 * 60 * h)
        end = stamp2time(time.time())
        print('[*] 第%d次更新态势感知安全告警 , '%num + start + ' --- ' + end)
        ip = get_taishi(db,h)
        db.commit()
        # ip = db.query_ip('taishi',start,end)
        get_log(db,h,ip)
        db.close()
        # 5分钟刷新一次
        time.sleep(60*5)

def main(typ,h):
    db = Db()

    if (not os.path.exists('logs')):
        os.mkdir('logs')
    if typ == 'run':
        run(db,h)
    elif typ == 'output':
        export2log(db,h)

    elif typ == 'geo':
        export2geo(db,h)

    elif typ == 'black':
        export2blackip(db,h)

    elif typ == 'whois':
        get_whois(db,h)

    elif typ == 'sheepwall':
        weakpass2txt(db,h)
    db.close()




if __name__ == "__main__":

    opts, args = getopt.getopt(sys.argv[1:], '-h-t:-o-r-g-b-w-s', ['help', 'time=', 'output','run','geo','black','whois','sheepwall'])
    h = 0
    for opt_name, opt_value in opts:
        if opt_name in ('-h', '--help'):
            print("[*]  -t --time= [] hours ,最近多少小时的数据")
            print("[*]  -r --run  运行态势感知实时告警,默认5分钟一轮 ")
            print("[*]  -o --output  导出日志,可配合-t参数使用 ")
            print("[*]  -g --geo  导出攻击者地理位置信息,可配合-t参数使用 ")
            print("[*]  -b --black  导出ip黑名单,可配合-t参数使用 ")
            print("[*]  -w --whois  导出whois信息,可配合-t参数使用 ")
            print("[*]  -s --sheepwall  导出弱密码绵羊墙,可配合-t参数使用 ")


        if opt_name in ('-t', '--time'):
            h = int(opt_value)

        if opt_name in ('-r', '--run'):
            typ = 'run'
            main(typ,h)

        if opt_name in ('-o', '--output'):
            typ = 'output'
            main(typ,h)

        if opt_name in ('-g', '--geo'):
            typ = 'geo'
            main(typ,h)

        if opt_name in ('-b', '--black'):
            typ = 'black'
            main(typ,h)

        if opt_name in ('-w', '--whois'):
            typ = 'whois'
            main(typ,h)

        if opt_name in ('-s', '--sheepwall'):
            typ = 'sheepwall'
            main(typ, h)









