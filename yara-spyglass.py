import yara
import requests


rules = yara.compile(filepath='./rules/nginx.yara')

with open('testsites.txt','r') as testTargetFile:
    targets = testTargetFile.readlines()

    for target in targets:
        try:
            response = requests.get(target.rstrip())
        except:
            print("could not connect to {}".format(target))
            continue
        matches = rules.match(data=str(response.headers))
        if 'main' not in matches: print("{} had no matches".format(target.rstrip()))
        else:
            for match in matches['main']:
                if match['matches']: print('{} matched on {}'.format(target,match['rule']))

