import json
import sys
import validators
import tldextract
from multiprocessing import Pool

OUTPUT_PATH = "/data/"

def checkLine(line):
    
    data = json.loads(line.strip())

    # Check for valid domain name
    if validators.domain(data["name"]):
        # Write files for TLDs
        tld = tldextract.extract(data["name"]).suffix
        if tld in ["ad", "al", "at", "ax", "ba", "be", "bg", "by", "xn--90ais", "ch", "cz", "de", "dk", "ee", "es", "eu", "fi", "fo", "fr", "uk", "gb", "gg", "gi", "gr", "hr", "hu", "ie", "im", "is", "it", "je", "li", "lt", "lu", "lv", "mc", "md", "me", "mk", "xn--d1alf", "mt", "nl", "no", "pl", "pt", "ro", "rs", "xn--90a3ac", "ru", "su", "xn--p1ai", "se", "si", "sj", "sk", "sm", "ua", "xn--j1amh", "va"]:
            with open(OUTPUT_PATH + tld + ".txt", 'a', buffering=1*(1024**2)) as outputFile:
                # write example.org,93.184.216.34
                outputFile.write(data["name"] + "," + data["value"] + "\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: ./generateFilesToAnalyze.py FILENAME")
        sys.exit()

    pool = Pool()
    with open(sys.argv[1], 'r') as f:
        pool.map(checkLine, f)
       
            
            

if __name__ == '__main__':
    main()