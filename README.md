# Focus Wall

Focus Wall is a local macOS website blocker for people who want weekends-only access to distracting websites. It blocks common attention sinks from Monday to Friday and automatically allows them again on Saturday and Sunday.

It is intentionally simple: it runs on your Mac, uses Brisbane time by default, and manages a section of `/etc/hosts` through a root-owned LaunchDaemon.

## What It Blocks

The starter list includes:

- YouTube
- X / Twitter
- LinkedIn
- Reddit
- Instagram
- Facebook
- TikTok
- Twitch
- Netflix
- Discord web
- Hacker News
- Several common news sites

You can add or remove domains after installation.

## How It Works

Focus Wall installs a macOS LaunchDaemon that checks the current policy every 30 seconds.

- Monday to Friday: blocked domains are written into `/etc/hosts`.
- Saturday and Sunday: Focus Wall removes its managed block entries.
- Timezone: `Australia/Brisbane`.
- Recovery: weekday emergency unlocks require a generated recovery key and a delay.

The recovery key is shown once during installation. Focus Wall stores only a salted hash of that key.

## Important Limits

Focus Wall is self-control software, not enterprise security software. A determined Mac administrator can remove any local blocker eventually. The aim is to make distraction inconvenient enough that you pause before opening the site.

It currently blocks websites through DNS/hosts resolution. It does not block native apps.

## Requirements

- macOS
- Python 3
- Admin access for installation

## Install

Clone the repo:

```sh
git clone https://github.com/robbiepeck/Focus-Wall.git
cd Focus-Wall
```

Run the installer:

```sh
./install.sh
```

The installer will ask for your macOS admin password. It then prints a recovery key once:

```text
Store this recovery key somewhere inconvenient but recoverable.
```

Keep that key somewhere you can access when genuinely needed, but not somewhere you will casually reach for it.

## Commands

Check the current policy:

```sh
focuswall status
```

List blocked domains:

```sh
focuswall list-domains
```

Add domains:

```sh
sudo focuswall add-domain example.com www.example.com
```

Remove domains:

```sh
sudo focuswall remove-domain example.com www.example.com
```

Cancel unlocks and reapply the current policy:

```sh
sudo focuswall block-now
```

## Emergency Unlock

On weekdays, emergency unlocks require the recovery key. By default, unlocks wait 30 minutes before taking effect and then last 60 minutes:

```sh
sudo focuswall emergency-unlock
```

You can change the delay and duration:

```sh
sudo focuswall emergency-unlock --delay-minutes 30 --duration-minutes 120
```

Cancel a pending or active unlock:

```sh
sudo focuswall cancel-unlock
```

## Uninstall

```sh
./uninstall.sh
```

Uninstall asks for the recovery key, stops the LaunchDaemon, removes Focus Wall's managed `/etc/hosts` entries, and removes installed files.

## Installed Locations

- `/usr/local/bin/focuswall`
- `/usr/local/lib/focuswall/focuswall.py`
- `/Library/LaunchDaemons/com.pecksol.focuswall.plist`
- `/Library/Application Support/FocusWall/config.json`
- `/etc/hosts` between Focus Wall markers

## Test Without Installing

Run the local self-test:

```sh
python3 focuswall.py self-test
```

This uses temporary files and does not touch your system hosts file.

## License

MIT
