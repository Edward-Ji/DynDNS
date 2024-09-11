"""
MIT License

Copyright (c) 2023 Edward Ji

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

This script updates the DNS record on Cloudflare with the current external IP
address. It is meant to be run as a cron job on a Raspberry Pi. The external IP
address is obtained by either querying OpenDNS or by logging into the router.
The former is quicker but the latter serves as a backup in case OpenDNS is
down.
"""

from logging.handlers import RotatingFileHandler
import base64
import json
import logging
import os
import re
import subprocess

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
import requests


root_dir = os.path.dirname(os.path.realpath(__file__))
log_dir = os.path.join(root_dir, 'logs')
log_path = os.path.join(log_dir, 'dyndns.log')
auth_path = os.path.join(root_dir, 'auth.json')

# set up logging
if not os.path.exists(log_dir):
    os.makedirs(log_dir)
handler = RotatingFileHandler(
    log_path,
    maxBytes=5 * 1024 * 1024,
    backupCount=3
    )
formatter = logging.Formatter(
    '%(asctime)s %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
    )
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.addHandler(handler)

with open(auth_path, encoding='utf-8') as f:
    auth = json.load(f)


def get_ip_from_opendns():
    proc = subprocess.run(
        ['dig', '+short', 'myip.opendns.com', '@resolver1.opendns.com'],
        capture_output=True,
        text=True
        )
    if proc.returncode == 0:
        ip = proc.stdout.strip()
        logging.debug('proc success')
        return ip
    logging.debug(f'proc failure {proc.returncode}')
    return None


def get_ip_from_router():
    """
    Get the external IP address by logging into the router and querying the
    certain page. This is a backup in case OpenDNS is down. The make and model
    of the router is Archer VR1600v. The router uses RSA encryption to encrypt
    the username and password.
    """
    router_url = 'http://192.168.1.1/'

    session = requests.Session()
    session.headers = {
        'Referer': router_url,
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:60.0)'
        }

    # get the index page to wake the system, do not remove
    r = session.get(router_url)
    logging.debug(f'getParm text: {r.text}')

    # get the public key in the form of exponent and modulus
    r = session.post(f'{router_url}cgi/getParm')
    logging.debug(f'getParm text: {r.text}')

    matches = re.findall(r'"([^"]*)"', r.text)
    e, n = map(lambda s: int(s, 16), matches)

    # reconstruct the public key and encrypt the username and password
    # the make of the router uses PKCS1v15 padding
    public_key = rsa.RSAPublicNumbers(e, n).public_key()
    username = auth['router']['username'].encode()
    password = base64.b64encode(auth['router']['password'].encode())
    username_ciphered = public_key.encrypt(username, padding.PKCS1v15()).hex()
    password_ciphered = public_key.encrypt(password, padding.PKCS1v15()).hex()

    # login
    params = {
        'UserName': username_ciphered,
        'Passwd': password_ciphered,
        'Action': 1,
        'LoginStatus': 0,
        }
    r = session.post(f'{router_url}cgi/login', params=params)
    logging.debug(f'response text: {r.text}')

    # get the token
    r = session.get(router_url)
    token, = re.findall(r'var token="([^"]*)"', r.text)
    session.headers.update({'Tokenid': token})

    # get the external IP address
    session.headers.update({
        'Connection': 'keep-alive',
        'Content-Type': 'text/plain'
        })
    r = session.post(
        f'{router_url}cgi?1',
        '[WAN_PPP_CONN#2,1,1,0,0,0#0,0,0,0,0,0]0,0\r\n'
        )
    logging.debug(f'response text: {r.text}')
    ip, = re.findall(r'externalIPAddress=(.*)', r.text)

    # logout
    r = session.post(
        f'{router_url}cgi?8',
        '[/cgi/logout#0,0,0,0,0,0#0,0,0,0,0,0]0,0\r\n'
        )
    logging.debug(f'response text: {r.text}')

    return ip


def main():
    # get external IP
    ip = get_ip_from_opendns()
    if ip is None:
        ip = get_ip_from_router()
    logging.debug(f'{ip = }')

    # update Cloudflare DNS record
    cloudflare_url = (
        'https://api.cloudflare.com/client/v4/'
        f'zones/{auth["cloudflare"]["zone_identifier"]}/'
        f'dns_records/{auth["cloudflare"]["identifier"]}'
        )

    payload = {
        'content': ip,
        'name': auth["cloudflare"].get('name', '@'),
        'type': auth["cloudflare"].get('type', 'A'),
        'ttl': 300,
        }
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth["cloudflare"]["bearer"]}'
        }

    r = requests.put(cloudflare_url, json=payload, headers=headers, timeout=10)
    logging.info(f'response text: {r.text}')


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logging.exception(e)
