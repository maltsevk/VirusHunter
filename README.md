# VirusHunter
It's python script to search for malicious files on the Internet using search queries (used Yandex search engine).

To interact with the server, the console browser Selenium PhantomJS was used, which allows for a long time not to receive blocking from too frequent requests to the search server.

The developed program searches the Internet for malicious files by collecting files from web sites obtained from issuing a search engine and analyzes files on specialized anti-virus resources (VirusTotal).

The developed program supports the following functionalities:
* it has a list of search queries used by cybercriminals to attract users to its resource (including the names of common software);
* performs queries in search engines based on a compiled list of queries;
* gets a list of links to third-party sites that are accessible from the specified web page. Parsing the page and finding URLs on it;
* finding a form on the website and links leading to downloading executable files (exe, msi), documents (rtf, doc, docx, xls, ppt, pptx, pdf and others), Javascript code, Flash files (swf), Java applications (jar), Android applications (APK). Parsing URL paths for the presence of extensions of the required files;
* implementation of saving information about the sites from which data is downloaded (IP-address, URL-address);
* it downloads files and calculates meta-information about them (md5);
* checks the file for malicious functionality using the capabilities of the VirusTotal resource (free API).

For faster parsing, the script is multi-process (4 processes):
1. main process that creates others, waits for them to complete, creates two queues for synchronizing processes and marks the program runtime.
2. parser process, which for all search queries recorded in the search_queries.txt file, recursively searches for links to other sites and puts into one of two queues links to download files of those formats that are predefined in the program (exe, msi, rtf, pdf , doc, docx, xls, js, ppt, pptx, swf, jar, apk). The program is given a certain constant, which means the depth of recursion in the recursive search for references. Also, this process keeps statistics on the number of found links, websites.
3. process that takes download links from the queue, downloads these files and puts the names of the downloaded files into another one to be checked on VirusTotal. Also, this leads the statistics of the number of downloaded files.
4. process that takes a file name from a queue, reads its hash and checks it with VirusTotal. Collects statistics on malicious and clean files by their types.

The program reads the text file trusted_sources.txt, which contains a list ("white" list) of sites that do not contain malware. For example, such sites are microsoft.com, skype.com, wikipedia.org, etc.
