# VirusHunter
It's python script to search for malicious files on the Internet using search queries.

The developed program searches the Internet for malicious files by collecting files from web sites obtained from issuing a search engine and analyzes files on specialized anti-virus resources (VirusTotal).

The developed program supports the following functionalities:
* it has a list of search queries used by cybercriminals to attract users to its resource (including the names of common software);
* performs queries in search engines based on a compiled list of queries;
* gets a list of links to third-party sites that are accessible from the specified web page. Parsing the page and finding URLs on it;
* finding a form on the website and links leading to downloading executable files (exe, msi), documents (rtf, doc, docx, xls, ppt, pptx, pdf and others), Javascript code, Flash files (swf), Java applications (jar), Android applications (APK). Parsing URL paths for the presence of extensions of the required files;
* implementation of saving information about the sites from which data is downloaded (IP-address, URL-address);
* it downloads files and calculates meta-information about them (md5);
* checks the file for malicious functionality using the capabilities of the VirusTotal resource (free API).
