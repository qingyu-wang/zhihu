#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Zhihu Session
[Info]
    Simulate Zhihu Login [Ref: https://github.com/zkqiang/Zhihu-Login]
"""

__author__ = 'qingyu-wang'
__github__ = 'https://github.com/qingyu-wang/zhihu'


import base64
import getpass
import hashlib
import hmac
import io
import json
import os
import pickle
import time
import logging

import matplotlib
matplotlib.use('QT5Agg')  # set matplotlib backend
import matplotlib.pyplot as plt
import requests

from PIL import Image


FILE_PATH = os.path.abspath(__file__)
ROOT_PATH = os.path.dirname(os.path.dirname(FILE_PATH))
COOKIE_PATH = '{}/log/zhihu_cookies.pkl'.format(ROOT_PATH)


class BasicSession(object):
    """Basic Session
    [Info]
        a basic session built with some common methods
    [Attribute]
        save_cookie: save cookies to a pickle file
        load_cookie: load cookies from a pickle file
    """
    def __init__(self, debug):
        self.debug = debug
        self.user_agent = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_6) ' + \
                          'AppleWebKit/537.36 (KHTML, like Gecko) ' + \
                          'Chrome/65.0.3325.181 Safari/537.36'
        self.session = requests.session()
        self.logger = self.init_logger()

    def init_logger(self):
        """Initialize Logger
        [Info]
            output type: standard error
            message level: DEBUG < INFO < WARNING < ERROR
        """
        format_log = '[%(name)s] [%(asctime)s] [%(levelname)s] %(message)s'
        format_date = '%Y-%m-%d %H:%M:%S'

        logger = logging.getLogger(__file__)
        handler = logging.StreamHandler()  # sys.stdout
        formatter = logging.Formatter(fmt=format_log, datefmt=format_date)

        handler.setFormatter(formatter)
        logger.addHandler(handler)

        if self.debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        return logger

    def save_cookie(self, cookie_path):
        """Save Cookies
        [Info]
            save cookies to a pickle file
        """
        if cookie_path is not None:
            cookiedir = os.path.dirname(cookie_path)
            if not os.path.isdir(cookiedir):
                os.makedirs(cookiedir)
            cookies = requests.utils.dict_from_cookiejar(self.session.cookies)
            pickle.dump(cookies, open(cookie_path, 'wb'))
            self.logger.info('save cookies [{}]'.format(cookie_path))
        return

    def load_cookie(self, cookie_path):
        """Load Cookies
        [Info]
            load cookies from a pickle file
        """
        cookies = pickle.load(open(cookie_path, 'rb'))
        self.session.cookies = requests.utils.cookiejar_from_dict(cookies)
        self.logger.info('load cookies [{}]'.format(cookie_path))
        return


class ZhihuSession(BasicSession):
    """Zhihu Account
    [Info]
        a zhihu session built with some common methods
    [Attribute]
        check_login: check login status
        login: make a login request
    """

    def __init__(self, lang='en', cookie_path=None, cookie_load=False, debug=False):
        super(ZhihuSession, self).__init__(debug)
        self.cookie_path = cookie_path
        self.cookie_load = cookie_load
        self.lang = lang


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
            self.logger.info('CHECK LOGIN: true')
            status = True
        else:
            self.logger.info('CHECK LOGIN: false')
            status = False

        return status

    def login(self):
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
                self.session.get(url=url, headers=headers)

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
                        print '[INPUT] click all upside-down characters, and press [enter] to continue'
                        plt.imshow(img)
                        points = plt.ginput(7)
                        captcha = {
                            'img_size': [200, 44],  # img.size = (400, 88)
                            'input_points': [[point[0]/2, point[1]/2] for point in points]
                        }
                        payload = {'input_text': json.dumps(captcha)}
                        plt.close('all')

                    else:
                        plt.imshow(img)
                        plt.show(block=False)
                        captcha = raw_input('[INPUT] enter the verification code: ')
                        payload = {'input_text': captcha}
                        plt.close('all')

                    # check captch first
                    resp = self.session.post(url=url, data=payload, headers=headers)
                    meta = json.loads(resp.content)
                    if 'success' in meta:
                        self.logger.info('VERIFY CODE: success')
                        break
                    else:
                        self.logger.error('VERIFY CODE: failed, please retry...')

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
                self.logger.debug(meta['error']['message'].encode('utf-8'))
                status = False
            else:
                status = True

            return status

        if self.cookie_load and self.cookie_path is not None and os.path.isfile(self.cookie_path):
            self.load_cookie(self.cookie_path)

        if self.check_login():
            status = True

        else:
            while True:
                username = '+86' + raw_input('[INPUT] username (mobile phone): ')
                password = getpass.getpass('[INPUT] password: ')

                timestamp = str(int(time.time()*1000))

                xsrf_token = _fetch_xsrf_token()
                captcha = _fetch_captcha(self.lang)
                signature = _build_signature(timestamp)

                login_params = {
                    'username': username,
                    'lang': self.lang,
                    'timestamp': timestamp,
                    'password': password,
                    'xsrf_token': xsrf_token,
                    'captcha': captcha,
                    'signature': signature
                }
                status = _login(params=login_params)

                if status:
                    self.logger.info('LOGIN: success')
                    break
                else:
                    self.logger.error('LOGIN: failed, please retry...')

            self.save_cookie(self.cookie_path)

        return status


def main():
    """Main
    [Info]
        a simple example
    """
    import argparse


    parser = argparse.ArgumentParser(description='Zhihu Session')
    parser.add_argument('--lang', type=str, default='en', metavar='language', help='language')
    parser.add_argument('--cookie_path', type=str, default=COOKIE_PATH, metavar='cookie_path', help='cookie path')
    parser.add_argument('--cookie_load', action='store_true', help='use former cookie')
    parser.add_argument('--debug', action='store_true', help='open debug mode')

    args = parser.parse_args()

    account = ZhihuSession(lang=args.lang, cookie_path=args.cookie_path, cookie_load=args.cookie_load, debug=args.debug)
    account.login()

    return


if __name__ == '__main__':
    main()
