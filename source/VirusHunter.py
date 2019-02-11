# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
from selenium import webdriver
from multiprocessing import Process, Queue

import hashlib, time, os
import virus_total_apis
import json, requests
import socket

API_KEY = '381e785f4923840ff2c44a85e611208c8cd0bc10d9dadd85957ace06935619d7'

SEARCH_ENGINE = 'https://yandex.ru/search/?lr=2&text='

FILE_FORMATS = ['.exe', '.msi', '.rtf', '.doc', '.docx', '.xls', '.js',
                '.ppt', '.pptx', '.pdf', '.swf', '.jar', '.apk']

PHANTOM_FILE = '\\phantomjs-2.1.1-windows\\bin\\phantomjs.exe'

RECURSION_DEPTH = 2

gLinkCounter = 0
gWebsiteCounter = 0

def checkFileViaVirusTotal(hash, virusTotal):
    response = virusTotal.get_file_report(hash)
    report = json.dumps(response, sort_keys=False, indent=4)

     # if requests per minute exceeded (204)
    if(str(report).find('"response_code": 204') != -1):
        time.sleep(5)
        return checkFileViaVirusTotal(hash, virusTotal)
    
    return report

def getHtml(url, browser):
    try:
        browser.get(url)
    except:
        return None
    return browser.page_source

def calculateFileHash(filename):
    with open(filename, 'rb') as file:
        data = file.read()
    return hashlib.md5(data).hexdigest()

def findSearchResultLinks(html, trustedSources):
    links = []
    flag = False
    
    soup = BeautifulSoup(html, 'html.parser')
    items = soup.find_all('h2', class_ = 'organic__title-wrapper typo typo_text_l typo_line_m')
    
    for item in items:
        link = item.a.get('href')
        
        for url in trustedSources:
            if(str(link).find(url) != -1):
                flag = True
                break

        if (flag is True):
            flag = False
            continue
        
        links.append(link)

    return links

def getRootAddress(link):
    index = link.find("/", 8, len(link))
    return link[0:index]

def writeFile(filename, data, mode):
    file = open(filename, mode)
    file.write(data)
    file.close()

def getNameFromLink(link):
    if (link[len(link) - 1] == '/'):
        link = link[0:(len(link) - 1)]

    return link[(link.rfind('/') + 1):len(link)]

def deleteHttpPart(url):
    if (url.find('https') != -1):
        return url[8:len(url)]
    return url[7:len(url)]

def downloadData(link):
    try:
        data = requests.get(link)
    except:
        return None
    
    return data

def createDirectory(directory):
    if not os.path.exists(directory):
        os.mkdir(directory)

def readFileLines(filename):
    with open(filename) as file:
        fileLines = [row.strip() for row in file]

    return fileLines

def findDownloadLinks(site, browser):
    
    downloadLinks = []
    
    root = getRootAddress(site)
    html = getHtml(site, browser)
    if html is None:
        return downloadLinks

    soup = BeautifulSoup(html, 'html.parser')
    items = soup.find_all('a', href=True)

    for item in items:
        link = item.get('href')
        if (link.find('http') == -1):
            link = root + link
        
        for fileFormat in FILE_FORMATS:
            #if (link.find(fileFormat, len(link) - 5, len(link)) != -1):
            if link.endswith(fileFormat):
                downloadLinks.append(link)

    return downloadLinks

def findExternalLinks(site, browser, trustedSources):
    flag = False
    links = []
    
    root = getRootAddress(site)
    html = getHtml(site, browser)
    if html is None:
        return links

    soup = BeautifulSoup(html, 'html.parser')
    items = soup.find_all('a', href=True)

    for item in items:
        link = item.get('href')
        if (link.find('http') == -1):
            link = root + '/' + link

        for url in trustedSources:
            if(str(link).find(url) != -1):
                flag = True
                break

        if (flag is True):
            flag = False
            continue
            
        # for site section (example: yandex.ru/images)
        slashIndex = link.rfind('/')
        dotIndex = link.rfind('.')

        if (link.find('.html') != -1 or dotIndex < slashIndex):
            links.append(link)

    return links

def exploreLink(link, directory, downloadLinksQueue, browser, trustedSources, depth):

    logFile = 'LogParser.txt'
    websitesList = []
    global gWebsiteCounter
    global gLinkCounter

    if (depth == 0):
        return

    log('  [*] Current link ' + ' (' + str(gLinkCounter) + '): ' + link, logFile)

    if getRootAddress(link) not in websitesList:
        websitesList.append(link)
        gWebsiteCounter += 1

    directory = directory + deleteHttpPart(getRootAddress(link)) + '\\'
    createDirectory(directory)
    createDirectory(directory + 'files\\')
    createDirectory(directory + 'analysis\\')
    createDirectory(directory + 'external_links\\')

    gLinkCounter += 1

    siteAddress = deleteHttpPart(getRootAddress(link))

    try:
        ip = socket.gethostbyname(siteAddress)
    except:
        ip = 'error'
    writeFile(directory + 'ip.txt', ip, 'w')
            
    downloadLinks = findDownloadLinks(link, browser)
    for downLink in downloadLinks:
        # push pair to queue
        downloadLinksQueue.put([downLink, directory])

    directory = directory + 'external_links\\'
    externalLinks = findExternalLinks(link, browser, trustedSources)
    for extLink in externalLinks:
        exploreLink(extLink, directory, downloadLinksQueue, browser, trustedSources, depth - 1)
    
    return

def log(info, filename):
    print(info)
    with open(os.getcwd() + '\\' + filename, 'a') as file:
        file.write(info + '\n')

def getFileFormat(filename):
    for format in FILE_FORMATS:
        if filename.find(format) != -1:
            return format

def parsingProcess(downloadLinksQueue):

    global gLinkCounter
    global gWebsiteCounter

    browser = webdriver.PhantomJS(os.getcwd() + PHANTOM_FILE)
    logFile = 'LogParser.txt'
    searchQueries = readFileLines('search_queries.txt')
    trustedSources = readFileLines('trusted_sources.txt')

    for query in searchQueries:
        log('[*] Processing query: ' + query, logFile)
        currentQuery = SEARCH_ENGINE + query.replace(' ', '%20')

        # get links from the first search page 
        html = getHtml(currentQuery, browser)
        if html is None:
            continue
        searchResults = findSearchResultLinks(html, trustedSources)

        # directory for the current query
        directory = os.getcwd() + '\\' + query + '\\'
        createDirectory(directory)
        for link in searchResults:
            exploreLink(link, directory, downloadLinksQueue, browser, trustedSources, RECURSION_DEPTH)

    log('[*] Total links found: ' + str(gLinkCounter), logFile)
    log('[*] Total websites found: ' + str(gWebsiteCounter), logFile)
    browser.quit()
    return

def downloadingProcess(downloadLinksQueue, downloadedFilePathsQueue):

    logFile = 'LogDownloader.txt'
    totalCounter = 0

    while True:
        if (downloadLinksQueue.empty() != True):
            # pair -> (link, directory)
            pair = downloadLinksQueue.get()
            if (pair[0] == 0):
                downloadedFilePathsQueue.put([0, 0])
                break

            data = downloadData(pair[0])
            if data is None:
                continue

            filename = getNameFromLink(pair[0])
            fullpath = pair[1] + 'files\\' + filename
            writeFile(fullpath, data.content, 'wb')

            log('[*] (' + str(totalCounter) + ') ' + filename + ' has been downloaded', logFile)

            # put pair (directory, filename) to queue
            downloadedFilePathsQueue.put([pair[1], filename])
            totalCounter += 1
        else:
            time.sleep(3)

    log('[*] Total files downloaded: ' + str(totalCounter), logFile)
    return


def analyzingProcess(downloadedFilePathsQueue):

    virusTotal = virus_total_apis.PublicApi(API_KEY)
    logFile = 'LogAnalyzer.txt'
    totalCounter = 0
    malwareCounter = 0
    formatFilesCountDict = {}

    for fileFormat in FILE_FORMATS:
        formatFilesCountDict[fileFormat] = [0, 0]

    while True:
        if (downloadedFilePathsQueue.empty() != True):
            # pair -> (directory, filename)
            pair = downloadedFilePathsQueue.get()
            if (pair[0] == 0):
                break
        
            # calculating hash of the file
            hash = calculateFileHash(pair[0] + 'files\\' + pair[1])
        
            report = checkFileViaVirusTotal(hash, virusTotal)
            format = getFileFormat(pair[1])
            formatFilesCountDict[format][0] += 1
            totalCounter += 1

            log('[*] Starting to analyze (' + str(totalCounter) + ') ' + pair[1], logFile)
            # if this file is malware
            if (str(report).find('true') != -1):
                malwareCounter += 1
                formatFilesCountDict[format][1] += 1
                log('  [*] Malware detected (' + str(malwareCounter) + '): ' + pair[1], logFile)
            else:
                log('  [*] This file is clean: ' + pair[1], logFile)
            
            writeFile(pair[0] + 'analysis\\' + pair[1] + '.result.txt', report, 'w')

        else:
            time.sleep(3)

    log('[*] Total files analyzed: ' + str(totalCounter), logFile)
    log('[*] Total malware files: ' + str(malwareCounter), logFile)
    log('[*] Format table (total downloaded / malicious)', logFile)

    for format in gFormatFilesCount:
        log(' ' + format + '\t' +
        str(formatFilesCountDict[format][0]) + ' / ' +
        str(formatFilesCountDict[format][1]), logFile)

    return

def main():
    
    startTime = time.time()

    linksQueue = Queue()
    pathsQueue = Queue()
    
    parser = Process(target=parsingProcess, args=(linksQueue,))
    downloader = Process(target=downloadingProcess, args=(linksQueue, pathsQueue))
    analyzer = Process(target=analyzingProcess, args=(pathsQueue,))

    parser.daemon = True
    downloader.daemon = True
    analyzer.daemon = True
    
    parser.start()
    downloader.start()
    analyzer.start()

    parser.join()
    downloader.join()
    analyzer.join()

    pathsQueue.close()
    linksQueue.close()

    endTime = time.time()
    
    log('[*] Total runtime in minutes: ' + str(int((endTime - startTime) / 60)), 'LogMain.txt')

if __name__ == '__main__':
    main()
