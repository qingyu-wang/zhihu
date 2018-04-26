#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Zhihu Session
[Info]
    Simulate Zhihu Login 
"""
__author__ = 'qingyu'
__github__ = 'https://github.com/zkqiang/Zhihu-Login'

import base64
import hashlib
import hmac
import io
import json
import os
import pickle
import time

import matplotlib.pyplot as plt
import requests

from PIL import Image


class BasicSession(object):
    """Basic Session
    [Info]
        a basic session built with some common methods
    [Attribute]
        save_cookies: save cookies to a pickle file
        load_cookies: load cookies from a pickle file
    """
    def __init__(self):
        self.user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) ' + \
                          'AppleWebKit/537.36 (KHTML, like Gecko) ' + \
                          'Chrome/65.0.3325.181 Safari/537.36'
        self.session = requests.session()

    def save_cookies(self, cookiefile):
        """Save Cookies
        [Info]
            save cookies to a pickle file
        """
        cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
        pickle.dump(cookies, open(cookiefile, 'wb'))
        return

    def load_cookies(self, cookiefile):
        """Load Cookies
        [Info]
            load cookies from a pickle file
        """
        cookies = pickle.load(open(cookiefile, 'rb'))
        self.session.cookies = requests.utils.cookiejar_from_dict(cookies)
        return


class ZhihuSession(BasicSession):
    """Zhihu Account
    [Info]
        a zhihu session built with some common methods
    [Attribute]
        check_login: check login status
        login: make a login request
    """
    def __init__(self):
        super(ZhihuSession, self).__init__()
        self.cookiefile = './zhihu_cookies.pkl'

    def check_login(self):
        """Check login
        [Info]
            检查登录状态，访问登录页面出现跳转则是已登录
            status_code: 302 => 已登录 [跳转]
            status_code: 200 => 未登录
            如登录成功保存当前 Cookies
        [Return]
            status: login status [boolean]
        """
        url = 'https://www.zhihu.com/signup'
        headers = {
            'Connection': 'keep-alive',
            'Host': 'www.zhihu.com',
            'User-Agent': self.user_agent
        }
        resp = self.session.get(url=url, headers=headers, allow_redirects=False)

        if resp.status_code == 302:
            status = True
        else:
            status = False

        return status

    def login(self, load_cookies=True):
        """Sign Zhihu Account
        [Info]
            模拟登录知乎
            1. 模拟打开登录页面
            2. 模拟获取验证码
            3. 模拟提交登录请求
        [Return]
            status: login status [boolean]
        """
        def _fetch_xsrf_token():
            """Fetch XSRF Token from Cookies
            [Info]
                模拟进入登录页面
                通过 Cookies 获取 xsrf_token
            [Return]
               xsrf_token: xsrf token [string]
            """
            if '_xsrf' not in self.session.cookies:

                url = 'https://www.zhihu.com/signup'
                headers = {
                    'Connection': 'keep-alive',
                    'Host': 'www.zhihu.com',
                    'User-Agent': self.user_agent
                }
                resp = self.session.get(url=url, headers=headers)

                if resp.status_code != 200:
                    raise Exception('http status code is {} [!=200]'.format(resp.status_code))

            xsrf_token = self.session.cookies['_xsrf']

            return xsrf_token

        def _fetch_captcha(lang):
            """Fetch Captcha
            [Info]
                请求验证码的 API 接口
                如果需要验证码会返回 base64 编码的图片
                无论是否需要验证码都需要请求一次
            [Argument]
                lang: 选择语言，"en" 是输入4位验证码，"cn" 是选择倒转的中文
            [Return]
                captcha: 返回验证码 [string]
            """
            url = 'https://www.zhihu.com/api/v3/oauth/captcha?lang={lang}'.format(lang=lang)
            headers = {
                'Authorization': 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20',
                'Connection': 'keep-alive',
                'Host': 'www.zhihu.com',
                'Referer': 'https://www.zhihu.com/signup',
                'User-Agent': self.user_agent
            }

            resp = self.session.get(url=url, headers=headers)
            meta = json.loads(resp.content)

            if meta['show_captcha']:
                while True:
                    resp = self.session.put(url=url, headers=headers)
                    meta = json.loads(resp.content)
                    img = Image.open(io.BytesIO(base64.b64decode(meta['img_base64'])))

                    if lang == 'cn':
                        print '[INFO] 点击所有倒立的汉字，按 [回车] 提交'
                        plt.imshow(img)
                        points = plt.ginput(7)
                        captcha = {
                            'img_size': [200, 44],  # img.size = (400, 88)
                            'input_points': [[point[0]/2, point[1]/2] for point in points]
                        }
                        payload = {'input_text': json.dumps(captcha)}
                        plt.close()

                    else:
                        plt.imshow(img)
                        plt.show(block=False)
                        captcha = raw_input('[INFO] 请输入图片里的验证码，按 [回车] 提交：')
                        payload = {'input_text': captcha}
                        plt.close()

                    # check captch first
                    resp = self.session.post(url=url, data=payload, headers=headers)
                    meta = json.loads(resp.content)
                    if 'success' in meta:
                        print '[INFO] 验证码正确'
                        break
                    else:
                        print '[ERROR] 验证码错误，请重试'

            else:
                captcha = ''

            return captcha

        def _build_signature(timestamp):
            """Build Signature
            [Info]
                利用 Hmac 算法计算返回签名
                通过全局搜索 [command+option+F] 'signature' 得到具体算法
            [Argument]
                timestamp: 时间戳，毫秒，字符串
            [Return]
                signature: 签名
            """
            grant_type = 'password'
            client_id = 'c3cef7c66a1843f8b3a9e6a1e3160e20'
            source = 'com.zhihu.web'

            key = 'd1b964811afb40118a12068ff74a12f4'
            msg = grant_type + client_id + source + timestamp

            signature = hmac.new(key=key, msg=msg, digestmod=hashlib.sha1).hexdigest()

            return signature

        def _login(params):
            """Sign In
            [Info]
                status_code: 201 => 登录成功
                status_code: 401 => 认证失败
            [Return]
                status: login status [boolean]
            """
            url = 'https://www.zhihu.com/api/v3/oauth/sign_in'
            payload = {
                'username': params['username'],
                'password': params['password'],
                'captcha': params['captcha'],
                'signature': params['signature'],
                'lang': params['lang'],
                'timestamp': params['timestamp'],
                'client_id': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
                'grant_type': 'password',
                'source': 'com.zhihu.web',
                'ref_source': 'homepage'
            }
            headers = {
                'Authorization': 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20',
                'Connection': 'keep-alive',
                'Origin': 'https://www.zhihu.com',
                'Referer': 'https://www.zhihu.com/signup',
                'X-Xsrftoken': params['xsrf_token'],
                'User-Agent': self.user_agent
            }
            resp = self.session.post(url=url, data=payload, headers=headers)

            if 'error' in resp.content:
                meta = json.loads(resp.content)
                print '[ERROR] {}'.format(meta['error']['message'].encode('utf-8'))
                status = False
            else:
                status = True

            return status

        # Main
        if load_cookies and os.path.isfile(self.cookiefile):
            self.load_cookies(self.cookiefile)

        if self.check_login():
            status = True

        else:
            while True:
                username = '+86' + raw_input('\n[INPUT] 请输入用户名(手机号): ')
                password = raw_input('[INPUT] 请输入密码: ')

                lang = 'cn'
                timestamp = str(int(time.time()*1000))

                xsrf_token = _fetch_xsrf_token()
                captcha = _fetch_captcha(lang)
                signature = _build_signature(timestamp)

                login_params = {
                    'username': username,
                    'lang': lang,
                    'timestamp': timestamp,
                    'password': password,
                    'xsrf_token': xsrf_token,
                    'captcha': captcha,
                    'signature': signature
                }
                status = _login(params=login_params)

                if status:
                    break

        self.save_cookies(self.cookiefile)

        return status


def main():
    """
    main
    """
    account = ZhihuSession()
    login_status = account.login(load_cookies=True)

    if login_status:
        print '[INFO] 登录成功'
    else:
        print '[INFO] 登录失败'

    return


if __name__ == '__main__':
    main()
