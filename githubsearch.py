# -*- coding: utf-8 -*-
import argparse
from cookielib import CookieJar
import urllib
import urllib2
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import ssl
from BeautifulSoup import BeautifulSoup as Soup

parser = argparse.ArgumentParser(description='Github Searcher - Designed to search Repositories for credentialed information')
parser.add_argument('--username', type=str, help="Github Username")
parser.add_argument('--password', type=str, help="Github Password")
parser.add_argument('--urls-only', type=bool, help ="Display only the URLs")
parser.add_argument('--domain', type=str, help="Domain to search")

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
username="user"
password="pass"
csrftoken = ""
initcookie = ""
cookies = ""
proxies = {
  'http': 'http://127.0.0.1:8080',
  'https': 'http://127.0.0.1:8080',
}
FoundURLs=[]
NumResults=1

def search(cookies, pageNo):
    searchstring='q="test.domain.com"+%26%26+password&type=code'
    url= "https://github.com/search?p=" + str(pageNo) + "&"
    print "Searching %s" % url+searchstring
    global FoundURLs
    global NumResults
    r = requests.get('https://github.com/search?p=' + str(pageNo) + '&' + searchstring, verify=False, cookies=cookies, proxies=proxies)
    html = r.text
    parsed_html = Soup(html)
    pages = []
    for i in parsed_html.body.findAll("a"):    
        if i.get('href').startswith('/search'):
            current = i.contents[0]
            try:
                int(current)
            except ValueError:
                pass
            else:
                pages.append(int(current))
    print pages
    NumResults = max(pages)            
    #print "There are " + str(max(pages)) + " pages"
    
    found = parsed_html.body.findAll("div", attrs={'class':'file-box blob-wrapper'})
    for i in found:
        
        currentlink = i.findAll("a")
        print "Sensitive information found starting at https://github.com/" + currentlink[0].get('href')
        FoundURLs.append("https://github.com" + currentlink[0].get('href'))
        print "=============================="
        lines = i.findAll("td", attrs={'class':'blob-code blob-code-inner'})
        for line in lines:
            print line.text
        print "=============================="

    ######
    #Maybe work on a RegEx here for to search for variants of
    #Only output those lines that match the regex, along with the URLs
    #Password = ""
    #Pass=""
    #Pass = ""
    # etc. etc.
    #
    #Fixing Output:
    #https://stackoverflow.com/questions/5598524/can-i-remove-script-tags-with-beautifulsoup
    
    #for i in found:
    #    if i.contents[0] != "":
    #        currentLine = stripMarkUp(i.contents[0])
    #        print i.contents[0]
    
    
    #for table in tables:
    #    for row in table.findall("td"):
    #        print row
            #print row      
    return

def getCookies(initcookie, csrf, user, passw):
    cookievals = dict(_gh_sess=initcookie)
    params= ({"commit":"Sign In","utf8":"%E2%9C%93","authenticity_token":csrf,"login":user,"password":passw})
    r = requests.post('https://github.com/session', data = params, cookies=cookievals, verify=False, proxies=proxies)
    cookies2 = r.cookies.get_dict()
    return cookies2
    
    
def getCSRF(url):
    global csrftoken
    global initcookie
    r = requests.get(url, verify=False, proxies=proxies)
    html = r.text
    parsed_html = Soup(html)
    csrftoken = parsed_html.body.find('input',{'name':'authenticity_token'})['value']
    cookies = r.cookies.get_dict()
    initcookie = cookies.get("_gh_sess")
    return

def stripMarkUp(line):
    line = line.strip('<span class="pl-mh">')
        

def generateReport():
    


print "Getting CSRF Token and Cookie..."
getCSRF("https://github.com/login")
print "Getting Cookies..."
cookies = getCookies(initcookie,csrftoken, username, password)  
print "Searching for sensitive data"    
search(cookies, 1)
for i in range(2,NumResults):
    print i
    search(cookies,i)
for link in FoundURLs:
    print link
