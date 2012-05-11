#!/usr/bin/env python
# -*- coding: utf-8 -*-

#author: shiweifu
#mail: shiweifu@gmail.com
#license: BSD

import httplib
import time
import oauth
import sys
import urllib
import re
import binascii
import urllib2
from urllib2 import Request, urlopen
import uuid

USERNAME = ""
PASSWD = ""
CONSUMER_KEY = ''   # 应用key
CONSUMER_SECRET = ''  # 应用secret

API_BASE_URL = "api.fanfou.com"

SORTKEYS = ["oauth_consumer_key",
"oauth_nonce",
"oauth_signature",
"oauth_signature_method",
"oauth_timestamp",
"oauth_token",
"oauth_version"]

_HTTP_GET = 0
_HTTP_POST = 1


class AccountVerifyException(Exception): 
    """docstring"""
    pass       

def request_to_header(request, realm=''):
    """Serialize as a header for an HTTPAuth request."""
    auth_header = 'OAuth realm="%s"' % realm
        # Add the oauth parameters.
    if request.parameters:
        for k, v in request.parameters.iteritems():
            if k.startswith('oauth_') or k.startswith('x_auth_'):
                auth_header += ', %s="%s"' % (k, oauth.escape(str(v)))
    return {'Authorization': auth_header}



def _send(path, method, headers, params, is_upload_photo=False):
    """ POST/GET data to server """
    #headers["Content-Type"] = "application/x-www-form-urlencoded"

    if is_upload_photo == False:
        body = urllib.urlencode(params) 
    else:
        body = params
    conn = httplib.HTTPConnection("api.fanfou.com", 80)
    conn.request(method, url = path, \
                 headers = headers, 
                 body = body)
    response = conn.getresponse() 

    if response.status == 200:
        return True, response.read()
    return False, response.read()

def _sign_headers(header, method, full_url, consumer_token, params, _access_token):
    """ call signature_request to set oauth_signature field """
    s2 = (header['Authorization'].replace('OAuth realm="",', 'OAuth'))
    header['Authorization'] = s2

    dic = eval("dict("+s2[6:]+")")

    if("oauth_signature" in dic):
        del dic["oauth_signature"]

    dic["oauth_nonce"] = binascii.b2a_hex(uuid.uuid4().bytes)
    
    for key, val in params.items():
        dic[key] = val

    dic["oauth_signature"] = _signature_request( \
                             consumer_token, 
                             method, \
                             url=full_url, \
                             args=dic,
                             _access_token=_access_token)
    dic["oauth_signature"] = urllib.quote(dic["oauth_signature"])
    
    sortlist = []
    
    for key in SORTKEYS:
        sortlist.append("%s=\"%s\"" % (key, dic[key]))
        
    auth_value = "OAuth "+", ".join(sortlist)

    header['Authorization'] = auth_value
    return header



def _signature_request(consumer_token, method, url, args, _access_token):
    """ return signature_request by params """
    params = {}
    params.update(args)

    req = oauth.OAuthRequest(method, url, params)
    sigmethod = oauth.OAuthSignatureMethod_HMAC_SHA1()
    return sigmethod.build_signature(req, consumer_token, _access_token)

def _http_call(_tok, _headers, _body, _consumer_token, _access_token):
    """ call example:
        _http_call(_HTTP_POST, \
                   "/status/upload.xml" \
                   headers, post_data)
        _http_call(_HTTP_GET, \
                   "/statuses/followers.xml" \
                   headers, params})
    """

    full_url = "".join(("http://", API_BASE_URL, _tok.url))
    # method = tok.method
    url = _tok.url

    if _tok.method == _HTTP_GET:
        #GET
        method = "GET"
        if _body != {}:        
            url = "".join((url, "?", urllib.urlencode(_body)))
            full_url = "".join(("http://", API_BASE_URL, url))
    else:
        #POST
        method = "POST"
    signed_headers = _sign_headers(
                                    _headers,
                                    method, full_url,  
                                    _consumer_token, 
                                    _body,
                                    _access_token)
    signed_headers["Content-Type"] = "application/x-www-form-urlencoded"
    return _send(url, method, signed_headers, _body)


def _encode_multipart(**kw):
    '''
    Build a multipart/form-data body with generated random boundary.
    '''
    boundary = '----------%s' % hex(int(time.time() * 1000))
    data = []
    for k, v in kw.iteritems():
        data.append('--%s' % boundary)
        if hasattr(v, 'read'):
            # file-like object:
            ext = ''
            filename = getattr(v, 'name', '')
            n = filename.rfind('.')
            if n != (-1):
                ext = filename[n:].lower()
            content = v.read()
#            data.append('Content-Disposition: form-data; name="%s"; filename="hidden"' % k)
            data.append('Content-Disposition: form-data; name="photo"; filename="%s"' % filename)
            data.append('Content-Length: %d' % len(content))
            data.append('Content-Type: %s\r\n' % _guess_content_type(ext))
            data.append(content)
        else:
            data.append('Content-Disposition: form-data; name="%s"\r\n' % k)
            data.append(v.encode('utf-8') if isinstance(v, unicode) else v)
    data.append('--%s--\r\n' % boundary)
    return '\r\n'.join(data), boundary

_CONTENT_TYPES = { '.png': 'image/png', \
                   '.gif': 'image/gif', \
                   '.jpg': 'image/jpeg', \
                   '.jpeg': 'image/jpeg', \
                   '.jpe': 'image/jpeg' }

def _guess_content_type(ext):
    """ return content type by ext"""
    return _CONTENT_TYPES.get(ext, 'application/octet-stream')


class UrlToken(object):
    """docstring for UrlToken"""
    url = ""
    method = -1
    must_has = "status"
    def __init__(self, _url, _method):
        super(UrlToken, self).__init__()
        self.url = _url
        self.method = _method


class APIUrlTokens(object):
    """docstring for UrlTokens"""
    status = {
                "update": UrlToken("/statuses/update.json", _HTTP_POST), \
                "destroy": UrlToken("/statuses/destroy.json", _HTTP_POST), \
                "replies": UrlToken("/statuses/replies.json", _HTTP_GET),
                "friends": UrlToken("/statuses/friends.json", _HTTP_GET),
                "mentions": UrlToken("/statuses/mentions.json", _HTTP_GET),
                "show": UrlToken("/statuses/show.xml", _HTTP_GET), 
                "followers": UrlToken("/statuses/followers.json", _HTTP_GET),
                "public_timeline": UrlToken("/statuses/public_timeline.json", _HTTP_GET),
                "user_timeline": UrlToken("/statuses/user_timeline.json", _HTTP_GET),                   
                "context_timeline": UrlToken("/statuses/context_timeline.json", _HTTP_GET),
                "home_timeline": UrlToken("/statuses/home_timeline.json", _HTTP_GET), \
            }

    search = {
        "public_timeline": UrlToken("/search/public_timeline.json", _HTTP_GET),
        "users": UrlToken("/search/users.json", _HTTP_GET),
        "user_timeline": UrlToken("/search/user_timeline.json", _HTTP_GET)
             }

    blocks = {
        "ids": UrlToken("/blocks/ids.json", _HTTP_GET),
        "blocking": UrlToken("/blocks/blocking.json", _HTTP_GET),
        "create": UrlToken("/blocks/create.json", _HTTP_POST),
        "exists": UrlToken("/blocks/exists.json", _HTTP_GET),
        "destroy": UrlToken("/blocks/destroy.json", _HTTP_POST)
            }

    users = {
        "tagged": UrlToken("/users/tagged.json", _HTTP_GET),
        "show": UrlToken("/users/show.json", _HTTP_GET),
        "tag_list": UrlToken("/users/tag_list.json", _HTTP_GET),
        "followers": UrlToken("/users/followers.json", _HTTP_GET),
        "recommendation": UrlToken("/users/recommendation.json", _HTTP_GET),
        "cancel_recommendation": UrlToken("/users/cancel_recommendation.json", _HTTP_POST),
        "friends": UrlToken("/users/friends.json", _HTTP_GET)
            }

    account = {
        "verify_credentials": UrlToken("/account/verify_credentials.json", _HTTP_GET),
        "update_profile_image": UrlToken("/account/update_profile_image.json", _HTTP_POST),
        "rate_limit_status": UrlToken("/account/rate_limit_status.json", _HTTP_GET),
        "update_profile": UrlToken("/account/update_profile.json", _HTTP_POST),
        "notification": UrlToken("/account/notification.json", _HTTP_GET),
        "update_notify_num": UrlToken("/account/update_notify_num.json", _HTTP_POST),
        "notify_num": UrlToken("/account/notify_num.json", _HTTP_GET)
            }

    saved_searches = {
        "create": UrlToken("/saved_searches/create.json", _HTTP_POST),
        "destroy": UrlToken("/saved_searches/destroy.json", _HTTP_POST),
        "show": UrlToken("/saved_searches/show.json", _HTTP_GET),
        "list": UrlToken("/saved_searches/list.json", _HTTP_GET)
            }

    photos = {
        "user_timeline": UrlToken("/photos/user_timeline.json", _HTTP_GET),
        "upload": UrlToken("/photos/upload.json", _HTTP_POST)
            }

    trends = {
        "list": UrlToken("/trends/list.json", _HTTP_GET)
            }

    followers = {
        "ids": UrlToken("/followers/ids.json", _HTTP_GET)
            }

    favourites = {
        "destroy": UrlToken("/favorites/destroy.json", _HTTP_POST),
        "favorites": UrlToken("/favorites.json", _HTTP_GET),
        "create": UrlToken("/favorites/create.json", _HTTP_POST)
            }

    friendships = {
        "create": UrlToken("/friendships/create.json", _HTTP_POST),
        "destroy": UrlToken("/friendships/destroy.json", _HTTP_POST),
        "requests": UrlToken("/friendships/requests.json", _HTTP_GET),
        "deny": UrlToken("/friendships/deny.json", _HTTP_POST),
        "exists": UrlToken("/friendships/exists.json", _HTTP_GET),
        "accept": UrlToken("/friendships/accept.json", _HTTP_POST),
        "show": UrlToken("/friendships/show.json", _HTTP_GET)
            }

    friends = {
        "ids": UrlToken("/friends/ids.json", _HTTP_GET)
            }

    direct_messages = {
        "destroy": UrlToken("/direct_messages/destroy.json", _HTTP_POST),
        "conversation": UrlToken("/direct_messages/conversation.json", _HTTP_GET),
        "new": UrlToken("/direct_messages/new.json", _HTTP_POST),
        "conversation_list": UrlToken("/privete_messages/conversation_list.json", _HTTP_GET),
        "inbox": UrlToken("/direct_messages/inbox.json", _HTTP_GET),
        "sent": UrlToken("/direct_messages/sent.json", _HTTP_GET)
            }

    def __getattr__(self, attr):
        if hasattr(self, attr):
            return getattr(self, attr)
        raise None

class FanfouHandle(object):
    """docstring for FanfouHandle"""
    def __init__(self, _tokens, _account):
        super(FanfouHandle, self).__init__()
        self.tokens = _tokens
        self.account = _account

    def __getattr__(self, attr):
        if self.tokens.has_key(attr):
            tok = self.tokens[attr]
        else:
            raise NotImplementedError

        def wrapper(**kw):
            """ return attr by attr module """            
            return _http_call(tok, self.account.get_headers(), kw, 
                       self.account.get_consumer_token(), self.account.get_access_token())
        return wrapper

class FanfouPhotoHandle(object):
    """docstring for FanfouPhotoHandle"""
    def __init__(self, _account):
        super(FanfouPhotoHandle, self).__init__()
        self.account = _account

    def upload(self, pic_name, status="upload img"):
        """ upload image to server """
        headers = self.account.get_headers()
        pic_f = open(pic_name, "rb")
        params, boundary = _encode_multipart(status=status, pic=pic_f)
        pic_f.close()
        full_url = "".join(("http://", API_BASE_URL, "/photos/upload.json"))
    #    http_body = {"photo": params}

        method = "POST"

        signed_headers = _sign_headers(headers, 
                                        method, full_url,  
                                        self.account.get_consumer_token(),
                                        {},
                                        self.account.get_access_token())

        signed_headers['Content-Type'] = 'multipart/form-data; boundary=%s' % \
                                         boundary
        return _send("/photos/upload.json", method, signed_headers, params, 
                    is_upload_photo=True)

    def user_timeline(self, **kw):
        """ get user photo timeline """
        tok = UrlToken("/photos/user_timeline.json", _HTTP_GET)
        return _http_call(tok, self.account.get_headers(), kw,
                          self.account.get_consumer_token(), 
                            self.account.get_access_token())


class FanfouLib(object):
    """docstring for FanfouLib"""
    def __init__(self, _account):
        super(FanfouLib, self).__init__()
        self.url_tokens = APIUrlTokens()
        self.status = FanfouHandle(self.url_tokens.status, _account)
        self.account = FanfouHandle(self.url_tokens.account, _account)
        self.search = FanfouHandle(self.url_tokens.search, _account)
        self.blocks = FanfouHandle(self.url_tokens.blocks, _account)
        self.users = FanfouHandle(self.url_tokens.users, _account)
        self.saved_searches = FanfouHandle(self.url_tokens.saved_searches, _account)
        self.photos = FanfouPhotoHandle(_account)
        self.trends = FanfouHandle(self.url_tokens.trends, _account)
        self.followers = FanfouHandle(self.url_tokens.followers, _account)
        self.favourites = FanfouHandle(self.url_tokens.favourites, _account)
        self.friendships = FanfouHandle(self.url_tokens.friendships, _account)
        self.friends = FanfouHandle(self.url_tokens.friends, _account)
        self.direct_messages = FanfouHandle(self.url_tokens.direct_messages, _account)
        
    def __getattr__(self, attr):
        #return self.status
       return getattr(self, attr)
        

class FanfouAccount(object):
    """create FanfouAccount object by fanfou id,password and Consumer key\
Consumer secret,if verify account failed,raise a VerifyException """

#    AUTHORIZE_URL = "http://fanfou.com/oauth/authorize"
    ACCESS_TOKEN_URL = "http://fanfou.com/oauth/access_token"
    VERIFY_URL = 'http://api.fanfou.com/account/verify_credentials.xml'

#    BASE_URL = "api.fanfou.com"

    def __init__(self,  _user, _passwd, _consumer_key, _consumer_secret):
        super(FanfouAccount, self).__init__()
        self.user = _user
        self.passwd = _passwd
        self.consumer = oauth.OAuthConsumer(_consumer_key, _consumer_secret)
        self.headers = ""
        self.signature_method = ""

        if self._verify_account() == False:
            raise AccountVerifyException()

    def _verify_account(self):
        """ if this function failed, please check your user ,passwd and \
        consumer_secret,consumer_key"""
        self._fetch_access_token()
        
        request = oauth.OAuthRequest.from_consumer_and_token(self.consumer,
                                                     token=self.oauth_token,
                                                     http_url=self.VERIFY_URL)
        request.sign_request(self.signature_method, \
                             self.consumer, \
                             self.oauth_token)
        self.headers = request_to_header(request)
        #print resp
        resp = urlopen(Request(self.VERIFY_URL, headers=self.headers))

        if resp.getcode()!= 200:
            return False
        return True

    def get_access_token(self):
        return self.access_token

    def _fetch_access_token(self):
        """ send request and get access_token """

        params = {}
        params["x_auth_username"] = self.user
        params["x_auth_password"] = self.passwd
        params["x_auth_mode"] = 'client_auth'
        request = oauth.OAuthRequest.from_consumer_and_token(self.consumer,
                                            http_url=self.ACCESS_TOKEN_URL,
                                            parameters=params)
        self.signature_method = oauth.OAuthSignatureMethod_HMAC_SHA1()
        request.sign_request(self.signature_method, self.consumer, None)
        headers = request_to_header(request)

        try:
            resp = urlopen(Request(self.ACCESS_TOKEN_URL, headers=headers))
        except urllib2.HTTPError, ex:
            print ex
            raise ex
        if(resp.getcode() != 200):
            raise AccountVerifyException()

        token = resp.read()
        m = re.match(r'oauth_token=(?P<key>[^&]+)&oauth_token_secret=(?P<secret>[^&]+)', token)
        self.oauth_token = oauth.OAuthToken(m.group('key'), m.group('secret'))
        self.oauth_key = m.group('key')
        self.oauth_secret = m.group('secret')

        self.access_token = oauth.OAuthConsumer(key=self.oauth_key, secret=self.oauth_secret)
        return True

    def get_headers(self):
        """ return a right header by basestring """
        return self.headers

    def get_consumer_token(self):
        """ return oauth.OAuthConsumer object """
        return self.consumer

def main():
    """ nothing """
    account = FanfouAccount(USERNAME, PASSWD, CONSUMER_KEY, CONSUMER_SECRET)
    lib = FanfouLib(account)
#    print lib.direct_messages.new(user="", text="hello")
#    print lib.status.update(status="饿死了，吃面去")
    print lib.photos.user_timeline()

if __name__ == '__main__':
    main()
