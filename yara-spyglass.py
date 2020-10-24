import yara
import requests
import argparse
import glob

def main():
    parser = argparse.ArgumentParser(description="Running Yara Rules against Target Sites' Responses")

    parser.add_argument("-t","--targets", type=str, required=True,
                        help="Text file of newline separated targets. These are anything that python requests can make a requests against.")
    parser.add_argument("--headerrules", type=str, default=".",
                        help="Path to header rules.")
    parser.add_argument("-c", "--contentrules", type=str,
                        help="Path to content rules.")
    parser.add_argument("--headersonly",action="store_true",
                        help="Run script only against response headers.")
    parser.add_argument("--ua", type=str,
                        help="[Request Header] User-Agent value string")
    parser.add_argument("--host", type=str ,default="python-requests",
                        help="[Request Header] Host value string")
    args = parser.parse_args()

    #Headers and Body Rules are separate.
    # Set up Header Filepaths here:
    header_filepaths = {}
    for idx,header_yara_file in enumerate(glob.glob(args.headerrules+'/**/*.yar', recursive=True)):
        header_filepaths["namespace"+str(idx)]=header_yara_file

    print("Loading in {} rules from {}. ".format(str(len(header_filepaths)),args.headerrules))

    header_rules = yara.compile(filepaths=header_filepaths)
    #content_rules = yara.compile()

    with open(args.targets,'r') as testTargetFile:
        targets = testTargetFile.readlines()

        for target in targets:
            #Trim off whitespace
            target = target.rstrip().lstrip()
            try:
                response = requests.get(target) #Consider prefetch.
            except:
                print("could not connect to {}".format(target))
                continue

            header_matches = header_rules.match(data=str(response.headers))
            #if not args.headersonly:
                #content_matches = content_rules.match(data=str(response.content))

            response.close()
            
            # Consider response.content for body matching.
            if not header_matches: print("{} had no header matches".format(target))
            else:
                for header_match in list(header_matches.values())[0]:
                    if header_match['matches']: print('[MATCH] {} header matched on {}'.format(target,header_match['rule']))
if __name__ == '__main__':
    main()