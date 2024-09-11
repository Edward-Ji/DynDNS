# DynDNS

Query OpenDNS or login to TP-Link Archer VR1600v router for your IP and update
Cloudflare DNS entry.

## Setup

Install Python and create a venv for this project.

```
python -m venv venv
```

Install the required packages.

```
venv/bin/pip install -r requirements.txt
```

Create a scheduled job to run every five minutes or so. Run

```
crontab -e
```

and in the editor, add the following line:

```
*/5 * * * * path/to/project/venv/bin/python path/to/project/main.py
```
