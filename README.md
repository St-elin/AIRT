# AIRT - Another (attribution?) Incident Response Tool

## Why?

Let's imagine you have a huge incident and you are sure that it is an APT case. You can just create a json layer of TTPs and let the the script make a simple attribution for you. In current release script will get you the top 10 likely related APTs to your case after layer submition.

## What am I have to do to make this work?

 - python3
 - pip3 install requests stix2 (prefer to use virtualenv)
 - web-accessible json layer

## Simple Example

```
>>> from AIRT import main_threat_actors
>>> main_threat_actors('https://raw.githubusercontent.com/St-elin/AIRT/main/NewIncident.json')
Wait For It...
[('APT29', 11), ('OilRig', 11), ('APT28', 11), ('APT39', 10), ('FIN6', 10), ('Operation Wocao', 10), ('Patchwork', 9), ('Sandworm Team', 9), ('menuPass', 8), ('Frankenstein', 8)]
```

## Spoiler

This tool is under developing now. The script can do basic things already, but surely, It can do more!)

From time to time I'll update repo with new features. Any contributors are welcome! =)
