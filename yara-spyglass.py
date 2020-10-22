import yara
import requests


rules = yara.compile(source='rule dummy {condition:true}')

x = requests.get('https://augustjohnson.net')

matches = rules.match(data=str(x.headers))

print(matches)