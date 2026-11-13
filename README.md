# Netzwächter

Android-App, die dauerhaft im Hintergrund prüft, ob Apps auf deinem Handy sich verdächtig verhalten
(Trojaner, Spyware, Stalkerware). Alles läuft **lokal auf dem Handy** – es werden keine Daten an Server gesendet.

## Was die App macht

| Funktion | Wie | Voraussetzung |
|---|---|---|
| **DNS-Wächter** | Lokaler VPN-Tunnel fängt *nur* DNS-Anfragen ab, ordnet sie der anfragenden App zu (`getConnectionOwnerUid`), prüft sie und reicht sie weiter. Restlicher Traffic läuft unberührt. | VPN-Erlaubnis (einmalig) |
| Blocklist | Domains aus `blocklist.txt` (Hosts-Format) werden blockiert + gemeldet | Datei im App-Ordner |
| Beobachtungsliste | Meldet Dienste, die gern zum Datenabfluss missbraucht werden (Telegram-Bot-API, ngrok, Dynamic-DNS, …) – außer bei Apps, bei denen das normal ist | – |
| Auffällige Domains | Zufällig aussehende Namen (DGA), DNS-Tunneling, sehr gleichmäßige „Beacon“-Verbindungen | – |
| **Upload-Wächter** | Alle 5 Min.: wie viel hat jede App gesendet? Alarm bei Upload mit ausgeschaltetem Bildschirm, riesigen oder einseitigen Uploads (so fällt z. B. das Versenden von Screenshots/Aufnahmen auf) | Nutzungszugriff |
| **App-Prüfung** | Findet Apps mit Spionage-Merkmalen: Bedienungshilfen, Geräteadmin, Benachrichtigungszugriff, Bildschirmaufnahme-Recht, SMS/Anrufliste, ohne Startsymbol, nicht aus dem Play Store | – |
| Autostart | Startet nach Neustart automatisch | – |

## Grenzen (bitte ehrlich lesen)

- **Kein Virenscanner, keine Garantie.** Es ist ein Frühwarnsystem.
- Inhalte sind verschlüsselt (HTTPS). Die App kann **nicht sehen, dass ein Screenshot verschickt wird** – nur, dass eine
  App ungewöhnlich viel hochlädt oder zu verdächtigen Zielen verbindet.
- Malware mit **fest eingebauter IP** oder eigenem **DNS-over-HTTPS** umgeht den DNS-Wächter. Der Upload-Wächter
  sieht sie trotzdem (aber ohne Zieladresse).
- Der Upload-Wächter ist grob: Android liefert die Datenmengen nur in Zeitfenstern.
- Nur **Android 10+**. Auf dem iPhone ist so etwas technisch nicht möglich.
- Für **dauerhaften** Schutz: Systemeinstellungen → VPN → Netzwächter → „Always-on VPN“ einschalten.
- Private DNS (DNS-over-TLS) in den Android-Einstellungen auf „Aus“/„Automatisch“ stellen, sonst geht DNS am Tunnel vorbei.

## Bauen

**Android Studio** (empfohlen): Ordner öffnen → warten bis Gradle fertig ist → Handy per USB anschließen
(Entwickleroptionen + USB-Debugging) → ▶ Run. Oder APK: `./gradlew :app:assembleDebug`
→ `app/build/outputs/apk/debug/app-debug.apk` aufs Handy kopieren und installieren.

Die Erkennungslogik liegt in `core/` (reines Kotlin, ohne Android) und ist getestet:

```
./gradlew :core:test
```

Das Android-Modul `app/` wird nur gebaut, wenn ein Android SDK gefunden wird (`local.properties` oder `ANDROID_HOME`).

## Aufbau

```
core/  Paket-/DNS-Parser, Heuristiken, Regeln, Analysatoren  (getestet, 16 Tests)
app/   GuardVpnService (DNS-Wächter), VolumeMonitor (Upload), AppScanner, AlertCenter, MainActivity
```

## Eigene Blockliste

Datei `blocklist.txt` im internen App-Ordner (`files/`), eine Domain pro Zeile oder Hosts-Format. Quellen z. B.
URLhaus (abuse.ch) oder StevenBlack/hosts. Ein Import-Knopf in der App ist noch nicht eingebaut.

## Status

Version 0.1: Die Erkennungslogik ist per Test geprüft. Die Android-Teile (`app/`) wurden geschrieben, aber noch nicht
auf einem echten Gerät getestet.
