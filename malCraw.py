import re
import sys
import time
import codecs
import gevent
import logging
import urlnorm
import datetime
import urllib
import urlparse
import requests
import tldextract

from gsb import client
from pprint import pprint
from gsb import datastore
from bs4 import BeautifulSoup
from spam.surbl import SurblChecker
from spam.spamhaus import SpamHausChecker

UTF8Writer = codecs.getwriter('utf8')
sys.stdout = UTF8Writer(sys.stdout)

urlsseen = set()
urlschecked = dict()
cookiejar = None
ds = None
sbc = None

safebrowse_apikey = 'APIKEY'
debug = False
want_safebrowse = True
want_spamhaus = False

def RateLimited(maxPerSecond):

    minInterval = 1.0 / float(maxPerSecond)
    def decorate(func):
        lastTimeCalled = [0.0]
        def rateLimitedFunction(*args,**kargs):
            elapsed = time.clock() - lastTimeCalled[0]
            leftToWait = minInterval - elapsed
            if leftToWait>0:
                time.sleep(leftToWait)
            ret = func(*args,**kargs)
            lastTimeCalled[0] = time.clock()
            return ret
        return rateLimitedFunction
    return decorate

def safebrowse_init(apikey, storename):

    global ds, sbc

    chunk_range_str = None
    num_expressions = None
    num_addchunks = None
    num_subchunks = None

    ds = datastore.DataStore(storename)

    sbc = client.Client(ds,
                        apikey=apikey,
                        use_mac=True)


def find_url(txt):
    urlfinder = re.compile( # stolen from django
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
        r'localhost|'  # localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)
    urllist = [ mgroups[0] for mgroups in urlfinder.findall(txt)]
    return urllist

def fix_urls(urls, hostinfo):

    ret = []
    for url in urls:
        if url:
            if not urlparse.urlparse(url).scheme:
                if not url.startswith('//'):

                    url = url.encode('utf8','ignore')
                    url = hostinfo['scheme'] + "://" + hostinfo['hostname'] + '/' + url
                    url = urlnorm.norm(url)
                else:
                    url = hostinfo['scheme'] + ':' + url


                if url.endswith('#'):
                    url = url[:-1]

                if url.startswith('javascript:'):
                    continue

            ret.append(url)
    return ret

def get_domain(url):
    domain = tldextract.extract(url)
    result = domain.domain + "." + domain.tld
    return result


def check_surbl(url):
    global urlschecked

    domain = get_domain(url)

    # check for links we cannot handle
    if url.startswith('http') or url.startswith('https'):
        # short cirquit (caching is good!)
        if urlschecked.has_key("surbl-" + domain):
            return urlschecked["surbl-" + domain]
        checker = SurblChecker()
        try:
            ret = checker.is_spam(url)
        except IndexError:
            return False
        urlschecked["surbl-" + domain] = ret
        return ret
    else:
        return False

def check_spamhaus(url):
    global urlschecked, want_spamhaus

    domain = get_domain(url)

    if not want_spamhaus:
        return False

    if url.startswith('http') or url.startswith('https'):
        # short cirquit (caching is good!)
        if urlschecked.has_key("sh-" + domain):
            return urlschecked["sh-" + domain]
        checker = SpamHausChecker()
        try:
            ret = checker.is_spam(url)
        except Exception:
            print("Whoops, trying again")
            return False
        urlschecked["sh-" + domain] = ret
        return ret
    else:
        return False

def check_safebrowse(url):
    global urlschecked, want_safebrowse, cookiejar, sbc

    ret = False

    if not want_safebrowse:
        return False

    if url.startswith('javascript:'):
        ret = False

    try:
        url = urllib.quote(url, safe="%/:=&?~#+!$,;'@()*[]").encode('utf-8')

        url = get_domain(url)

        if urlschecked.has_key('sb-' + url):
            return urlschecked['sb-' + url]

        matches = sbc.CheckUrl(url, debug_info=True)
        if len(matches) == 0:
            ret = False
        else:
            for listname, match, addchunknum in matches:
                if ret:
                    ret += '%s: addchunk number: %d: %s\n' % (listname, addchunknum, match)
                else:
                    ret = '%s: addchunk number: %d: %s\n' % (listname, addchunknum, match)


    except Exception:
        print("SBC: Skipped")
        ret = False

    urlschecked['sb-' + url] = ret

    return ret

def extract_urls(r, hostinfo):

    global urlsseen


    if r == None:
        return

    urls = []

    if r.headers['content-type'].startswith('text/html'):
        soup = BeautifulSoup(r.content)

        urls = [link.get('src') for link in soup.find_all('script')]
        urls += [link.get('href') for link in soup.find_all('a')]
        urls += [link.get('src') for link in soup.find_all('iframe')]
        urls += [link.get('href') for link in soup.find_all('link')]
        urls += [link.get('url') for link in soup.find_all('applet')]
        urls += [link.get('data') for link in soup.find_all('object')]
        print("Found %d references" % len(urls))
    elif r.headers['content-type'].startswith('application/javascript'):

        urls = find_url(r.text)
        pprint(urls)
    elif r.headers['content-type'].startswith('text/plain'):

        urls = find_url(r.text)
        pprint(urls)
    else:

        return []

    if urls:
        urls = fix_urls(urls, hostinfo)

        for url in urls:
            if url in urlsseen:
                urls.remove(url)

        for url in urls:
            if check_surbl(url):
                print("Malicious domain found on %s:\n\t %s" % (hostinfo['fullurl'], url))
                f = open('assets.txt', 'a')
                f.write('SURBL :' + str(hostinfo['fullurl']) + '\t=>\t' + url + '\n')
                f.close()
            if check_spamhaus(url):
                print("Spamhaus domain found on %s:\n\t %s" % (hostinfo['fullurl'], url))
                f = open('assets.txt', 'a')
                f.write('SPAMHAUS:' + str(hostinfo['fullurl']) + '\t=>\t' + url + '\n')
                f.close()
            ret = check_safebrowse(url)
            if ret:
                print("SAFEBROWSE: %url -> %s" % (hostinfo['fullurl'], ret))
                f = open('assets.txt', 'a')
                f.write('SAFEBROWSE: %s -> %s\n' % (hostinfo['fullurl'], ret))
                f.close()


        print("New links on this page." % len(urls))
        return urls
    else:
        return []


def print_url(r, *args, **kwargs):
    global urlsseen

    if r == None:
        return

    urlsseen.add(r.url)


def recurse_url(urls, domain):
    global urlsseen, cookiejar

    domain = get_domain(domain)

    while True:
        if len(urls) == 0:
            return

        for url in urls:
            if url in urlsseen:
                urls.remove(url)

        print("urls contains %d elements" % len(urls))

        urls = [x for x in urls if x is not None]

        hooks = {'response': print_url}

        rs = []
        urlindex = 0
        for url in urls:

            if url in urlsseen:
                if url in urls:
                    urls.remove(url)
                continue
            else:
                urlsseen.add(url)

            if get_domain(url) != domain:

                continue

            if url.startswith('javascript:'):
                continue


            if url.startswith('mailto:'):
                continue

            if url:
                url_lists = []

                print("Fetching %s. (%d in cache, %d pending)" % (url, len(urlsseen), len(urls)))
                headers = {  # Let's pretend we're internet explorer, because we can
                    'User-Agent': 'Mozilla/5.0 (compatible; MSIE 10.6; Windows NT 6.1; Trident/5.0; InfoPath.2; SLCC1; .NET CLR 3.0.4506.2152; .NET CLR 3.5.30729; .NET CLR 2.0.50727) 3gpp-gba UNTRUSTED/1.0',
                }
                try:
                    response = requests.get(url, hooks=hooks, headers=headers, cookies=cookiejar)
                except Exception as ex:
                    continue

                cookiejar = response.cookies
                pprint(cookiejar.get_dict())


                hostinfo = { 'hostname': urlparse.urlparse(url).hostname.encode('utf8'),
                             'scheme': urlparse.urlparse(url).scheme.encode('utf8'),
                             'fullurl':url.encode('utf8')}
                items = extract_urls(response, hostinfo)
                url_lists.append(items)
                url_lists = [x for x in url_lists if x is not None]
                urls += sum(url_lists, []) # flatten
                urlindex += 1


def main():
    global debug, safebrowse_apikey

    if debug:
        logging.basicConfig(level=logging.DEBUG)

    if want_safebrowse:
        print("Checking datastore for SBC")
        safebrowse_init(safebrowse_apikey, 'sbcstore')

    if len(sys.argv) < 2:
        sys.exit('Need list of urls')

    urllist = []
    for line in open(sys.argv[1]):
        url = line.strip()
        if not url.startswith('http'):
            url = 'http://' + url
        print("Added %s" % url)
        urllist.append(url)

    for url in urllist:
        recurse_url([url], url)

if __name__ == '__main__':
    sys.exit(main())
