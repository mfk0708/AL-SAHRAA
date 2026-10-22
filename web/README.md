# Deploying the front end – Contract Assessment Tools v3.2.2

The front end is a static web page. It has no build step on the server and needs no Node.js.

```
index.html     the application (all application code and styles are inside this one file)
config.js      where the page finds the back end (default: /api on the same site)
vendor/        libraries, fonts and OCR files the page loads – 16 MB, no internet needed
deploy/        ready-made web-server configurations: nginx.conf, web.config (IIS), apache.conf
```

## Option A – let the back end serve it (simplest)

The back end serves the front end itself. Put `index.html`, `config.js` and `vendor/` in the back end's `web/` folder and open `http://SERVER:8000`. The server installers already do this, so no web server is needed.

## Option B – your own web server (nginx, IIS or Apache) in front of the back end

Use this option when you want port 80/443, your company certificate, or an existing web farm. The web server hosts these files and forwards **`/api/`** to the back end, which runs on the same machine at `http://127.0.0.1:8000` by default.

The page and `/api` must be on the **same site** (same host name and port). Sign-in cookies are `SameSite=Strict`, and the page's security policy allows connections only to its own site. That is why the web server forwards `/api/` rather than the browser calling another host.

### nginx (Linux)

```bash
sudo mkdir -p /var/www/contract-assessment-tools
sudo cp -r index.html config.js vendor /var/www/contract-assessment-tools/
sudo cp deploy/nginx.conf /etc/nginx/sites-available/contract-assessment-tools   # RHEL: /etc/nginx/conf.d/contract-assessment-tools.conf
sudo ln -s /etc/nginx/sites-available/contract-assessment-tools /etc/nginx/sites-enabled/
sudo nano /etc/nginx/sites-available/contract-assessment-tools                   # set server_name, HTTPS certificate
sudo nginx -t && sudo systemctl reload nginx
```

### IIS (Windows Server)

1. Install the IIS modules **URL Rewrite** and **Application Request Routing**. In IIS Manager, open the server node, then *Application Request Routing Cache* → *Server Proxy Settings*, and tick **Enable proxy**.
2. Create a site (for example `C:\inetpub\cat`, port 80/443 with your certificate). Copy `index.html`, `config.js`, `vendor\` and `deploy\web.config` into the site folder.
3. Install the back end on the same server (`install\Install_on_Windows.cmd` in the server package). It listens on 127.0.0.1:8000.

### Apache httpd

Copy the files to `/var/www/contract-assessment-tools`, then copy `deploy/apache.conf` into the sites folder. Enable `proxy`, `proxy_http` and `headers` (`a2enmod proxy proxy_http headers`) and reload Apache.

### After the web server is set up

* Set `CAT_COOKIE_SECURE=1` in the back end's `cat.env` when users connect over HTTPS. Set `CAT_TRUSTED_PROXIES=127.0.0.1` so the audit trail records each user's real IP address. Then restart the back end.
* Open the site. You should see the sign-in page with "Server 3.2.1 · postgresql/sqlite database" under the form.
* If you see **"Server unavailable"**, the page loaded but `/api/` is not reaching the back end. Check that the service is running and check the proxy rule.

### Hosting under a sub-path

If the site lives at, for example, `https://intranet.company.ae/cat/`, change `config.js` to:

```js
window.CAT_SERVER = window.CAT_SERVER || { api: '/cat/api' };
```

Then forward `/cat/api/` to `http://127.0.0.1:8000/api/` in the web-server configuration.

## Updating

Replace `index.html` and `vendor/` with the files from the new release. Keep `config.js` if you changed it. `index.html` and `config.js` are never cached, so users get the new version on their next page load.

## Verified

With this exact build:

* nginx 1.24 served the front end and forwarded `/api/` to the back end.
* All 19 end-to-end browser tests passed: sign-in, saving, multi-user changes, company isolation, uploads, OCR, the in-app suite of 79 tests, and zero requests to any other host.
* nginx's configuration check (`nginx -t`) passed, and the page carried the security headers from `nginx.conf`.

The IIS and Apache configurations follow the same rules but were not run here.
