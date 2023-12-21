import asyncio
import aiohttp
import time
from multiprocessing import Pool
import os
import sys
import ipaddress
import validators


def chunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def generateUrls(domains):
    paths = [
        "/data/owncloud.log",
        "/data/nextcloud.log",
        "/nextcloud/data/nextcloud.log",
        "/owncloud/data/owncloud.log"
    ]

    urls = []
    for domain in domains:
        for path in paths:
            for protocol in ['http://', 'https://']:
                urls.append(protocol + domain + path)
    
    return urls


async def checkUrlVulnerability(url, session):
    output = url + ",false"

    try:
        async with session.get(url=url) as response:
            if response.status == 200:
                if '"reqId"' in (await response.content.read(2048)).decode("utf-8"):
                    output = url + ",true"

    except Exception:
        pass

    print(output)


async def checkUrls(urls):
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:96.0) Gecko/20100101 Firefox/96.0'
    }
    
    session_timeout = aiohttp.ClientTimeout(
        total=None, sock_connect=2, sock_read=2)
    async with aiohttp.ClientSession(timeout=session_timeout, headers=headers) as session:
        await asyncio.gather(*[checkUrlVulnerability(url, session) for url in urls])


def main():
    if len(sys.argv) != 2:
        print("Usage: ./fastScanner.py FILENAME")
        sys.exit()

    domains = []
    
    with open(sys.argv[1], 'r') as f:
        for line in f.readlines():
            # Remove whitespace
            line = line.strip()
            domains.append(line)
            
    # chunks with a maximum of 48000 domains per run (fits 2,4,6 or 8 CPUs best)
    # in order to not exhaust systems memory
    chunkedDomains = list(chunks(domains, 48000))

    for domains in chunkedDomains:
        chunkSize = int(len(domains) / os.cpu_count())
        if chunkSize == 0:
            chunkSize = len(domains)

        splitted = list(chunks(domains, chunkSize))

        with Pool() as p:
            p.map(checkIpAndScan, splitted)


def checkIpAndScan(lines):
    domains = []
    for line in lines:
        domain,ip = line.split(',')
        if validators.domain(domain):
            if ipaddress.IPv4Address(ip).is_global:
                domains.append(domain)

    urls = generateUrls(domains)
    asyncio.run(checkUrls(urls))


if __name__ == '__main__':
    main()
