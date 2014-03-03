import urllib3
from urllib import quote
from hashlib import sha1
import datetime
import json
import uuid
import hmac
import base64

signingkey = ""

def do_request(reqtype, url, fields):
    nonce = get_nonce()
    curts = str(unix_time())

    oauthfields = {'oauth_consumer_key':'HKsTwUpFMJdJl2ecl5xRyw',
                 'oauth_nonce': nonce,
                 'oauth_signature_method':'HMAC-SHA1',
                 'oauth_timestamp': curts,
                 'oauth_token':'1510521234-IDA23KHUVW7Ak5xmg0tQXanOopjvyIXU049jdhc',
                 'oauth_version':'1.0'}

    sig = get_signature(reqtype, url, oauthfields, fields)

    oauthheader = getoauthheader(sig, oauthfields)

    http = urllib3.PoolManager()
    r = http.request(reqtype,url,fields, {'Authorization':oauthheader})
    return r.data
    pass



def getoauthheader(sig, oauthfields):
    allfields =oauthfields.copy()
    allfields['oauth_signature'] = sig

    header = "OAuth "
    first = True
    for key in sorted(allfields.keys()):
        header = header + ('' if first else ', ') + key + '="' + quote(allfields[key],safe='') + '"'
        first = False

    return header


def get_signature(rtype, url, oauthfields, fields):
    global signingkey

    parm_string = get_parameterstring(oauthfields, fields)
    sig_base = rtype + '&' + quote(url,safe='') + '&' + quote(parm_string,safe='')
    return base64.b64encode(hmac.new(signingkey, sig_base, sha1).digest())


def get_parameterstring(oauthfields, fields):

    allfields = oauthfields.copy()
    allfields.update(fields)

    first = True

    fullstring = ''
    for key in sorted(allfields.keys()):
        fullstring = fullstring + ('' if first else '&') + quote(key,safe='') + '=' + quote(allfields[key],safe='')
        first = False

    return fullstring

def unix_time(dt = None):

    if dt == None:
        dt = datetime.datetime.utcnow()

    epoch = datetime.datetime.utcfromtimestamp(0)
    delta = dt - epoch
    return int(delta.total_seconds() )



def get_nonce():
    return uuid.uuid1().hex

def tst_get_sig():

    # using the know values off the twitter website
    # This was tricky to debug until these unit tests, and then it was easy
    # Testament to TDD

    oauthfields = {
              'oauth_consumer_key':'xvz1evFS4wEEPTGEFPHBog',
              'oauth_nonce': 'kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg',
              'oauth_signature_method':'HMAC-SHA1',
              'oauth_timestamp': '1318622958',
              'oauth_token':'370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb',
              'oauth_version':'1.0'
             }

    fields = {'include_entities': 'true',
              'status': 'Hello Ladies + Gentlemen, a signed OAuth request!'}

    ps = get_parameterstring(oauthfields, fields)

    if (ps == 'include_entities=true&oauth_consumer_key=xvz1evFS4wEEPTGEFPHBog&oauth_nonce=kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg&oauth_signature_method=HMAC-SHA1&oauth_timestamp=1318622958&oauth_token=370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb&oauth_version=1.0&status=Hello%20Ladies%20%2B%20Gentlemen%2C%20a%20signed%20OAuth%20request%21'):
        print "ps pass"


    sig = get_signature('POST','https://api.twitter.com/1/statuses/update.json',oauthfields,fields)
    if (sig == 'tnnArxj06cWHq44gCs1OSKk/jLY='):
        print "sig pass"

    head = getoauthheader(sig,oauthfields)
    if (head == 'OAuth oauth_consumer_key="xvz1evFS4wEEPTGEFPHBog", oauth_nonce="kYjzVBB8Y0ZFabxSWbWovY3uYSQ2pTgmZeNu2VS4cg", oauth_signature="tnnArxj06cWHq44gCs1OSKk%2FjLY%3D", oauth_signature_method="HMAC-SHA1", oauth_timestamp="1318622958", oauth_token="370773112-GmHxMAgYyLbNEtIKZeRNFsMKPR9EyMZeS9weJAEb", oauth_version="1.0"'):
        print "head pass"

    pass

def get_tweets(ticker):
    res = do_request('GET','https://api.twitter.com/1.1/search/tweets.json',{'q':'#' + ticker,'count':'100'})
    resobject = json.loads(res)
    statuses = resobject['statuses']
    for status in statuses:
        print  status['created_at'] + " " + status['user']['screen_name'] + " " + status['text']

    pass

def setsigningkey():
    secrets = json.loads(open('secrets').read())
    global signingkey
    signingkey = quote(secrets['appsecret'],safe='') + '&' + quote(secrets['usersecret'],safe='')

if __name__ == '__main__':

    setsigningkey()

    #tst_get_sig
    get_tweets('ORCL')




    #app.run()


