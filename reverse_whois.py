import requests
from lxml import etree
import whois

def get_uname(ips):
    f = open('whois.txt', 'w')
    url = "http://s.tool.chinaz.com/same"
    for ip in ips:

        param = {"s":ip}
        r = requests.get(url,params=param)
        tree = etree.HTML(r.text)
        li = tree.xpath('//ul[@class="ResultListWrap"]/li[contains(@class,"ReLists")]')

        for i in li :
            uname = i.xpath('./div[2]/a/text()')[0]
            title = get_title(uname)

            try:
                f.writelines('%s --- %s:%s'%(ip,uname,title)+'\n')
                f.writelines(whois.whois(uname)+'\n')

            except:
                f.writelines("no whois info! \n")
            f.writelines('-'*50 + '\n')
    f.close()
    return 1



def get_title(uname):
    url  = "http://s.tool.chinaz.com/ajaxsync.aspx"
    param = {'at':'title','url':uname}
    try:
        r = requests.post(url,params=param,timeout=3)
        return r.text
    except:
        return '--'
# xpath = //ul[@class="ResultListWrap"]/li[contains(@class,"ReLists")]
if __name__ == "__main__":

    f = open('banip.txt','r')
    for i in f:
        get_uname(i.strip())
