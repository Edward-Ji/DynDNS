# DynDNS

This repository provides an automated setup for running the DynDNS update
script every 5 minutes using a systemd timer.

## Prerequisites

1. **Fill in authentication details**
   
Copy the example file and update your Cloudflare credentials:

```bash
cp auth.json.example auth.json
```

Then edit `auth.json` and replace `null` values:

2. **Install dependencies**

Ensure you have [uv](https://docs.astral.sh/uv/) and install requirements:

```bash
uv sync
```

## Setup

Run the setup script as root to create and enable the systemd service and timer:

```bash
sudo ./setup
```

This will:

- Create `/etc/systemd/system/dyndns.service` and
`/etc/systemd/system/dyndns.timer`.
- Enable and start the timer to run every 5 minutes.

## Logs & Status

- **Check timer status**:
```bash
systemctl list-timers --all | grep dyndns.timer
```

- **View service logs**:
```bash
journalctl -u dyndns.service -f
```
