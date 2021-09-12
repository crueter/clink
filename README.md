Rewrite of my [fork](https://git.swurl.xyz/swirl/link) of [link](https://fsh.ee). Written in C using [Mongoose](https://cesanta.com).

Please access this project on my [Gitea](https://git.swurl.xyz/swirl/clink) instance, NOT GitHub.

# Differences from link
- Much smaller executable size
- Longer, more "secure" deletion keys
- No external libraries
- Speedier
- Smaller resource footprint

# Self-Hosting
You can host this yourself.

Note: all commands here are done as root.

## Building & Installing
To build this project, you'll need a libc implementation (only tested with glibc), optionally a separate libcrypt implementation, and Git. Most Linux distributions should have all of these by default, but in case yours doesn't:
- `pacman -S glibc libxcrypt git`
- `emerge --ask sys-libs/glibc dev-vcs/git`
- `apt install glibc git`

1. Clone this repository:

```bash
git clone https://git.swurl.xyz/swirl/clink && cd clink
```

2. Compile:
```bash
make
```

3. Now, you need to install. NGINX and systemd files are provided in this project; you may choose not to install them.

For all install commands, you may optionally provide `prefix` and `DESTDIR` options. This is useful for packagers; i.e. for a PKGBUILD: `make prefix=/usr DESTDIR=${pkgdir} install`.

Available install commands are as follows:
- `make install` installs the executable, NGINX, and systemd files.
- `make install-bin` installs the executable file.
- `make install-systemd` installs the systemd file, as well as its environment file.
- `make install-nginx` installs the NGINX file.

For example, on a non-systemd system using NGINX, you would run `make install-bin install-nginx`.

4. If using systemd, change the environment file to reflect your desired options:
```bash
vim /etc/clink.conf
```

5. You can now enable and start the service:
```bash
systemctl enable --now clink
```

The server should now be running on localhost at port 8080.

## NGINX Reverse Proxy
An NGINX file is provided with this project. Sorry, no support for Apache or lighttpd or anything else; should've chosen a better HTTP server.

For this, you'll need [NGINX](https://nginx.org/en/download.html) (obviously), certbot, and its NGINX plugin. Most Linux distributions should have these in their repositories, i.e.:
- `pacman -S nginx certbot-nginx`
- `emerge --ask www-servers/nginx app-crypt/certbot-nginx`
- `apt install nginx python-certbot-nginx`

This section assumes you've already followed the last.

1. Change the domain in the NGINX file:
```bash
sed -i 's/your.doma.in/[DOMAIN HERE]' /etc/nginx/sites-available/clink
```

2. Enable the site:
```bash
ln -s /etc/nginx/sites-{available,enabled}/clink
```

3. Enable HTTPS for the site:
```bash
certbot --nginx -d [DOMAIN HERE]
```

4. Enable and start NGINX:
```bash
systemctl enable --now nginx
```

If it's already running, reload:
```bash
systemctl reload nginx
```

Your site should be running at https://your.doma.in. Test it by going there, and trying the examples. If they don't work, open an issue.

# Contributions
Contributions are always welcome.

# FAQ
## A user has made a link to a bad site! What do I do?
Clean it up, janny!

Deleting a link can be done simply by running:
```bash
rm /srv/clink/*/BADLINKHERE
```

Replace `/srv/clink` with whatever your data directory is.

## Can I prevent users from making links to specific sites (i.e. illegal content)?

## Can I blacklist certain words from being used in short links?
No. While it might be possible through some NGINX stuff, **this is not supported nor it is encouraged.**

## Is this an IP grabber?
No, unless someone links to grabify or something. If access logs are turned on, then the server administrator can see your IP, but management of access logs is up to them.

## Can I use this without a reverse proxy?
Probably, I don't know. Won't have HTTPS though, so either way, I heavily recommend you use a reverse proxy.

## What's the seed for?
The seed is used for generating deletion keys (as a salt). Do not share it whatsoever. I recommend using a seed under 16 characters, as if it is less than 16 characters, random characters will be appended to the salt, making "guessing" the deletion key harder.

## What operating systems are supported?
I've only tested it on my Arch Linux server, but it should work perfectly fine on all Linux distributions. Probably doesn't work on Windows.

## Can I run this in a subdirectory of my site?
Yes. Simply put the `proxy_pass` directive in a subdirectory, i.e.:
```
location /shortener {
    proxy_pass http://localhost:8080;
}
```

## Why'd you make this?
While the original link was by far the best link shortener I could find, it had a few problems:
- No query-string support: had to make POST requests
- Didn't decode URLs
- SQLite is not the greatest storage method out there
- No pre-provided systemd or NGINX files
- No `install` target for the makefile

The first two are mostly problems when using them with specific services; i.e. PrivateBin, which expects to be able to use query-strings and encoded URLs.

So, seeing those problems, I decided to fork it. However, Go is absolute anal cancer (~300 line file results in a 8MB executable), so I decided to write it in C (and now, it's ~250 lines and results in a ~60KB executable). Also, I like C.
