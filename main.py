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


def main():
    # get external IP
    ip = get_ip_from_opendns()
    if ip is None:
        logging.warning("failed to get IP from OpenDNS")
        return
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
