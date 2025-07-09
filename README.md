# Thefinals - HackMyVM Writeup

![Thefinals Icon](Thefinals.png)

## Übersicht

*   **VM:** Thefinals
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Thefinals)
*   **Schwierigkeit:** Easy
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 26. Juni 2025
*   **Original-Writeup:** https://alientec1908.github.io/Thefinals_HackMyVM_Easy/
*   **Autor:** Ben C.

---

**Disclaimer:**

Dieser Writeup dient ausschließlich zu Bildungszwecken und dokumentiert Techniken, die in einer kontrollierten Testumgebung (HackTheBox/HackMyVM) angewendet wurden. Die Anwendung dieser Techniken auf Systeme, für die keine ausdrückliche Genehmigung vorliegt, ist illegal und ethisch nicht vertretbar. Der Autor und der Ersteller dieses README übernehmen keine Verantwortung für jeglichen Missbrauch der hier beschriebenen Informationen.

---

## Zusammenfassung

Die Box "Thefinals" erforderte eine gründliche Web-Enumeration und die Ausnutzung verschiedener Schwachstellen. Nach der initialen Identifizierung offener Ports (SSH und HTTP), wurde ein Apache Webserver entdeckt, der einen Blog auf Basis von Typecho hostete. Die Analyse des Blogs zeigte eine Stored Cross-Site Scripting (S-XSS) Schwachstelle in der Kommentarfunktion.

Durch das Einschleusen eines bösartigen JavaScript-Tags in einen Kommentar konnte bei der Anzeige des Kommentars im Admin-Panel eine weitere Schwachstelle ausgenutzt werden: Ein Theme-Editor, der das Bearbeiten von Theme-Dateien erlaubte. Über die S-XSS-Schwachstelle wurde JavaScript injiziert, das wiederum den Theme-Editor in einem versteckten Iframe lud und PHP-Code (eine Reverse Shell) in eine Theme-Datei schrieb. Der Zugriff auf die manipulierte Theme-Datei ermöglichte eine erste Shell als der Webserver-Benutzer (`apache`).

In der `apache`-Shell wurden Systeminformationen und Dateiberechtigungen untersucht. Dabei wurde die Datenbankkonfiguration gefunden, die Anmeldedaten für die Typecho-Datenbank enthielt. Zudem wurde ein lokal laufender Dienst entdeckt, der periodisch Base64-kodierte Daten über UDP sendete. Diese Daten enthielten einen SSH-Private Key, der dekodiert und für den Login als Benutzer `scotty` verwendet wurde.

Als `scotty` wurde eine `sudo`-Regel gefunden, die die Ausführung des Binaries `/sbin/secret` als Root ohne Passwort erlaubte. Die Ausführung dieses privilegierten Binaries gewährte direkten Root-Zugriff, was die Erlangung des Root-Flags ermöglichte.

## Technische Details

*   **Betriebssystem:** Unix / Alpine Linux (basierend auf Nmap-Erkennung und `uname -a` Output in Shell)
*   **Offene Ports:**
    *   `22/tcp`: SSH (OpenSSH 9.9)
    *   `80/tcp`: HTTP (Apache httpd 2.4.62)
    *   `1337/udp`: Unbekannter Dienst (lokal gebunden, sendet Base64-Daten)

## Enumeration

1.  **ARP-Scan:** Identifizierung der Ziel-IP (192.168.2.64).
2.  **`/etc/hosts` Eintrag:** Hinzufügen von `thefinals.hmv` zur lokalen hosts-Datei.
3.  **Nmap Scan:** Identifizierung offener Ports 22 (SSH) und 80 (HTTP). Apache 2.4.62 wurde erkannt.
4.  **Web Enumeration (Port 80):**
    *   Zeigte eine Webseite mit dem Titel "THE FINALS".
    *   Nikto Scan: Fund von fehlenden Sicherheits-Headern, erlaubte TRACE Methode, Directory Indexing auf `/css/`, `/images/`.
    *   Feroxbuster: Entdeckung von Verzeichnissen wie `/blog/`, `/screenshots/`, `/blog/admin/`, `/blog/install/`, und spezifischen PHP-Dateien im Blog-Bereich.
    *   Analyse des Blogs (Typecho): Erkundung von Blog-Posts (`/archives/X/`) und Funktionen (`/search/`, Kommentarfunktion).
    *   Search Function (`/search/`): Zeigte Potenzial für HTML/XSS-Injection (z.B. im Titel).
    *   Comment Function (`/archives/1/comment` POST): Tests zeigten, dass Special Characters in `author` gefiltert wurden, aber HTML/Script-Tags in `text` injiziert werden konnten (Stored XSS).

## Initialer Zugriff (Apache Shell via S-XSS & RCE)

1.  **S-XSS Ausnutzung:** Eine Stored XSS Schwachstelle wurde in der Kommentarfunktion des Blogs entdeckt. Ein `<script>` Tag, das auf eine vom Angreifer gehostete `shell.js` Datei zeigte, wurde in das Textfeld eines Kommentars injiziert.
2.  **`shell.js` Payload:** Eine JavaScript-Datei (`shell.js`) wurde erstellt und auf der Angreifer-Maschine gehostet. Dieses Skript wurde durch den S-XSS getriggert, wenn ein Administrator (oder jemand mit den entsprechenden Rechten) den Kommentar im Blog sah.
3.  **Theme Editor RCE:** Das `shell.js` Skript nutzte eine weitere Schwachstelle im Typecho-Admin-Panel (Zugang zum Theme Editor unter `/blog/admin/theme-editor.php`) aus. Es lud den Theme Editor in einem versteckten Iframe und manipulierte den Inhalt einer Theme-Datei (z.B. `/blog/usr/themes/default/404.php`), um PHP Code (eine Reverse Shell Payload) einzufügen.
4.  **Erste Shell:** Durch den Zugriff auf die modifizierte Theme-Datei (`http://thefinals.hmv/blog/usr/themes/default/404.php`) wurde der injizierte PHP-Code ausgeführt, was zur Etablierung einer Reverse Shell auf Port 443 der Angreifer-Maschine führte.
5.  **Ergebnis:** Eine Shell wurde als Benutzer `uid=102(apache)` erlangt.

## Lateral Movement & Post-Exploitation (apache -> scotty)

1.  **Systemerkundung als `apache`:** In der `apache`-Shell wurde das Dateisystem untersucht.
2.  **DB Credentials:** Die Typecho-Datenbankkonfigurationsdatei (`/var/www/html/blog/config.inc.php`) wurde gefunden. Sie enthielt die Anmeldedaten für den Datenbankbenutzer `typecho_u` mit Passwort `QLTkbviW71CSRZtGWIQdB6s`.
3.  **Datenbankzugriff:** Mit diesen Anmeldedaten konnte auf die lokal laufende MariaDB zugegriffen und die `typecho_users` Tabelle ausgelesen werden, die unter anderem den Hash des `staff` Benutzers enthielt (nicht direkt für den nächsten Schritt verwendet).
4.  **UDP Broadcast Sniffing:** `netstat` und `lsof` zeigten einen lokal laufenden Dienst, der auf UDP Port 1337 sendete. `nc -ulnvp 1337` wurde verwendet, um die gesendeten Daten abzufangen. Diese enthielten eine Base64-kodierte Zeichenkette.
5.  **SSH Key Fund:** Die Base64-Zeichenkette wurde dekodiert und stellte sich als OpenSSH Private Key heraus.
6.  **SSH Login als `scotty`:** Der dekodierte Schlüssel wurde in einer Datei gespeichert, die Berechtigungen auf 600 gesetzt (`chmod 600 scotty_key`), und für den SSH-Login verwendet. Der Benutzername "scotty" wurde vermutlich aus dem Log (`/var/log/scotty-main.log`) abgeleitet, das ebenfalls als `apache` zugänglich war. Der Login als `scotty` mit dem Schlüssel war erfolgreich.

## Privilegieneskalation (scotty -> root)

1.  **User Flag:** Das User Flag (`user.flag`) wurde im Home-Verzeichnis eines anderen Benutzers (`/home/june/`) gefunden.
2.  **Sudo-Regel für `scotty`:** Als Benutzer `scotty` wurde `sudo -l` ausgeführt. Die entscheidende `sudo`-Regel erlaubte die Ausführung von `/sbin/secret` als Root ohne Passwort: `(ALL) NOPASSWD: /sbin/secret`.
3.  **`/sbin/secret` Ausführung:** Das privilegierte Binary `/sbin/secret` wurde mit `sudo /sbin/secret` ausgeführt. Basierend auf dem Protokoll gewährte die Ausführung dieses Binaries direkten Root-Zugriff (es erschien eine Root-Shell-Prompt).
4.  **Root-Zugang:** Direkte Root-Rechte wurden erlangt.
5.  **Root Flag:** Die Datei `root.flag` im `/root`-Verzeichnis wurde gefunden und ihr Inhalt ausgelesen.
6.  **Weitere DB-Credentials:** In der Root-Shell konnte auf weitere Systemdateien zugegriffen werden, was die Datenbank-Anmeldedaten für die `secret` Datenbank (`root:BvIpFDyB4kNbkyqJGwMzLcK`) enthüllte (diese waren für die System-Root-Eskalation nicht notwendig, aber zeigten eine weitere Kompromittierungsmöglichkeit).

## Flags

*   **user.flag:** `flag{4b5d61daf3e2e5ba57019f617012ad0919c2a6c29e11912aeadef2820be8f298}` (Gefunden unter `/home/june/user.flag`)
*   **root.flag:** `flag{8c5daa407626d218e962041dd8fd8f37913e56e32a6f06725da403175be0b9ff}` (Gefunden unter `/root/root.flag`)

---
