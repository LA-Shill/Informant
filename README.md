

<h1 align="center">INFORMANT</h1>
<h3 align="center">Contactless 'Active' Reconnaissance Asset Discovery and Vulnerability Assessment Tool</h3>
<p align="center">
  <a href="https://github.com/LA-Shill/Informant/blob/master/LICENSE">
    <img alt="License: GNU V3" src="https://img.shields.io/badge/License-GNU_V3-4e73df.svg" target="_blank"/>
  </a>
  <a href="https://twitter.com/liamshill">
    <img alt="Twitter: LA-Shill" src="https://img.shields.io/twitter/follow/liamshill.svg?style=social" target="_blank" />
  </a>
</p>
<p align="center">
  <a href="https://github.com/LA-Shill/Informant">
    <img src="https://i.ibb.co/10dz06c/informant.png" alt="Informant">
  </a>
  <p align="center">
 Informant is a web-based contactless 'active' reconnaissance asset discovery and vulnerability assessment platform. Utilising scan data from various Internet-wide scanning and passive DNS projects to discover and evaluate the security of a given exposed Internet-facing attack surface.  All known-vulnerability data is pulled from the <a href="https://nvd.nist.gov/">National Vulnerability Database (NVD)</a> which the U.S. government maintains.
</p>

<p align="center">
      The Informant platform has been developed as part of my final year degree Hons project. However, its potential use cases strive far beyond academia, with functionality rivalling that of enterprise solutions. Key features include: Historical data viewing, Known-vulnerability assessment, maximum total rDDoS potential, risky port analysis, automated statistical data overviews and vulnerable by default configuration common vulnerabilities and exposures (CVE) detection. 
This tool's indirect detection methods used to retrieve asset information ensure the targeted assets are never aware of your reconnaissance attempts.
</p>

<p align="center">
Please be aware that the project is currently in <b>early</b> development and should be treated as such, with the experimental vulnerable by default configuration flagging feature being in its infancy. This project was intended to be an academic proof of concept, which is reflected in the quality of the code. However, large sections of code are currently being re-written to improve the overall readability and performance of the codebase.
</p>

<p align="center">
  Research surrounding the tool can be found <a target="_blank" href="https://github.com/LA-Shill/Informant-Research">here</a>.
  
## Table of Contents

* [Getting Started](#getting-started)
  * [Dependencies](#core-dependencies)
  * [Installation](#linux-installation)
    * [Manual](#linux-installation)
    *  [~~Docker~~](#docker-installation) **(WIP)**
   * [Limitations](#limitations)
* [Usage](#usage)
  * [Launching](#startup)
  * [Features](#feature-overview)
  * [Modules](#modules)
* [Contributing](#contributing)
* [License](#license)

## Getting Started
<p align="center">
Informant is currently under <b>heavy</b> development and only comes as a standalone web-based application. The application relies on numerous dependencies and requires access to at least one valid <a href="https://shodan.io/api">Shodan</a>, <a href="https://censys.io/api">Censys</a> or <a href="https://binaryedge.io/api">BinaryEdge</a> API key to function. In addition to a Redis and MongoDB instance. All input and retrieved data is stored locally.
</p>

### Core Dependencies

* Python 3.6 or later
* MongoDB 2.2 or later
* Redis Server
* Pip3
  * Flask
  * Flask-PyMongo
  * Censys
  * Shodan
  * Pybinaryedge
  * Dnsdb
  * Tldextract
  * RapidFuzz
  * PyMongo
  * Requests
  * Redis
  * RQ (Redis Queue)
  * Beautifulsoup4
  * WTForms
  * Urllib3
  * Python-dotenv
  * More-itertools
  * Bson
  * Collections
  * Netaddr
  * Ipaddress
  * Ipwhois
  * Pyvis
  
 <b><sub><sup>*Python dependencies will shrink as the tool evolves and the codebase is further optimised.</sup></sub></b>

### Linux Installation

1. Install and start [MongoDB](https://docs.mongodb.com/manual/tutorial/install-mongodb-on-ubuntu/)

```bash
# Install MongoDB
sudo apt-get install -y mongodb

# Start MongoDB service
sudo systemctl start mongodb
```

2. Install [cve-search](https://github.com/cve-search/cve-search) and populate MongoDB (timely process . . .)  
_note **cve-search** is designed to work on **Linux only** - However can be adapted for **Windows**, get in touch if you need a hand. This entire step can be skipped however the tool will not be able to conduct the known vulnerability identification process._

```bash
# Download repo 
sudo git clone https://github.com/cve-search/cve-search.git

# Install dependencies
sudo pip3 install -r requirements.txt

# Create and populate CVEDB in MongoDB
./sbin/db_mgmt_cpe_dictionary.py -p

# then . . patience . .
./sbin/db_mgmt_json.py -p

# then . . . a lot more patience . . .
./sbin/db_updater.py -c
```

3. Install and start [redis](https://redis.io/) server

```bash
# Install Redis Server
sudo apt install redis-server

# Start the Redis Server
sudo systemctl start redis
```

4.  Install **Informant**

```bash
# Download repo
sudo git clone https://github.com/LA-Shill/Informant.git

# Access directory
cd Informant

# Install dependencies
sudo pip3 install -r requirements.txt
```

5.  Configure the following parameters within the default .env file according to your setup (in most instances the configure below will work straight out of the box but is highly insecure)
```bash
DB_HOST= 127.0.0.1
DB_PORT= 27017
CORE_MONGO_DB= "mongodb://127.0.0.1:27017/core"
VUL_MONGO_DB= "mongodb://127.0.0.1:27017/cvedb"
REDISTOGO_URL= "redis://:@127.0.0.1:6379/dev"
```



### Limitations and Known Issues
1. Informant is currently programmatically hard limited to retrieving a maximum of 1000 IWS records per target range to help prevent against accidental excessive credit usage.

2. Performance deteriorates significantly when handling multiple millions of records. This is being worked on as a priority, with multiple solutions already in the works.

3. The active based fraudulent geolocation feature is currently disabled and will be re-enabled in the next major patch. All operational methods within Informant follow the CAR process and do <b>not</b> directly connect with target networks.

4. Percentage change statistics are currently disabled. This functionality will be re-enabled during the next major code overhaul due to performance issues.

5. Censys and Onyphe are not currently utilised to their full potential. Data retrieval from Censys is limited to a finite array of protocols to lessen the platforms' credit use during large scans - this will be addressed in the next major update.

## Usage
### Startup

1. Create a worker (preferably run this in the background using screen)
```bash
# Start RQ worker (redis)
# Please note that the REDISTOGO_URL must be set in memory! Alternatively replace line #13 in the worker.py script with your correct connection details.
python3 worker.py
```
2. Start the development server
```bash
# Start dev web server on local address(s) (port is modifiable within the wsgi.py file and a app.ini file is provided for use with third-party web servers such as Nginx)
python3 wsgi.py
```

3. Navigate to INFORMANT in your browser of choice at: [127.0.0.1:5000](http://127.0.0.1:5000)
  <img src="https://i.ibb.co/dLnM3wc/search.png" target="_blank" />

4. Finally, add your API key(s) and configure your parameters by navigating to the settings tab located at: [127.0.0.1:5000/settings](http://127.0.0.1:5000/settings)
  <img src="https://i.ibb.co/3RbfHC0/settings.jpg" target="_blank" />

5.  Scan your first IP or CIDR block by utilising the primary search bar or by creating a new project and manual initialising an asset scan.

### Feature Overview

##### Project Risk Overview
  <img src="https://i.ibb.co/g60t8zv/risk-overview.jpg" target="_blank" />
  
 - The latest data within the time frame selected will be displayed.
  
 - Data displayed is in time-series and linked directly with the interactive timeline bar.
 
 - Overview of Passive DNS records flagged as external, for asset detection outwith your targeted network ASN.
 
 - Overview of risky IWS assets, please note that devices flagged as obfuscated services are not deemed a risk.
 
 - Data drilldowns and exportation is available via the dropdown menu and hyperlinked IP addresses. Please note that no hyperlink within the tool will connect you to the target system.
<img width="125px" height="125px" src="https://i.ibb.co/h9tm4sL/drilldown.jpg" target="_blank" />
 
 <b> Current list of program flags </b>
 
 <img width="600px" height="425px" src="https://i.ibb.co/19FHHGD/Flags.jpg" target="_blank" />

##### Internet-wide Scanning Data Breakdown
 <img src="https://i.ibb.co/zf2JfxJ/IWS-Breakdown.jpg" target="_blank" />

 - Breakdown of all ingested Internet-wide scanning data.
 - Data exportable in CSV format.
 
##### Passive DNS Data Breakdown
 <img src="https://i.ibb.co/9yvF10r/pdns.jpgg" target="_blank" />

 - Breakdown of all passive DNS data.
 - Data exportable in CSV format.
 
##### Exposed Attack Surface Map
 <img src="https://i.ibb.co/d0T0hbS/Map.jpg" target="_blank" />
 
 - Interactive graph showing the exposed attack surface, based on current timeline selection and constructed using IWS and PDNS data.
 -  Data exportable in HTML format.


##### Individual Asset Risk Assessment
 <img src="https://i.ibb.co/RgSs4jT/Capture.jpg" target="_blank" />
 
 - The latest data within the time frame selected will be displayed.
 - Overview of all data stored on an asset.


##### Individual Project Settings
 <img src="https://i.ibb.co/TccMT5K/settings-project.jpg" target="_blank" />
 
##### Key Features
* Powerful non-direct asset discovery capabilities
* Passive DNS hostname enrichment
* Fraudulent geolocation validation (direct scanning feature, currently disabled)
* Vulnerable by default CVE identification
* Service banner to common platform enumeration (CPE) reconstruction
* Known-vulnerability risk assessment
* Maximum asset bandwidth amplification factor (BAF) rDDoS prediction
* Obfuscated service banner detection
* High-risk port list

 ### Modules

##### Internet-wide Scanning Projects
| Name    | API Key Required        |
| ------- | ------------------- |
| <a href="https://www.shodan.io/" target="_blank">Shodan</a>         | Yes       |
| *<a href="https://censys.io/" target="_blank">Censys</a>          | Yes       |
| <a href="https://www.binaryedge.io/" target="_blank">BinaryEdge</a>         | Yes       |
| **<a href="https://www.onyphe.io/" target="_blank">Onyphe</a>        | Yes       |

 <sub>*Data ingest is limited to popular protocols/ports (Limitation due to <b>free</b> academic requirement of the project and will be rectified in the future)</sub>
 
 <sub>** Platform needs to be used in conjunction with another Internet-wide Scanner (Limitation due to <b>free</b> academic requirement of the project and will be rectified in the future)</sub>
 
 ##### Passive DNS Sources
| Name    | API Key Required        |
| ------- | ----------------------- |
| <a href="https://www.threatcrowd.org/" target="_blank">ThreatCrowd</a>         | No       |
| <a href="https://www.threatminer.org/" target="_blank">ThreatMiner</a>          | No       |
| <a href="https://www.robtex.com/" target="_blank">Robtex</a>         | No       |
| <a href="https://daloo.de/" target="_blank">Daloo</a>        | No       |
| <a href="https://www.farsightsecurity.com/" target="_blank">FarSight</a>        | Yes       |
| <a href="https://opendata.rapid7.com/" target="_blank">DNSGrep</a>        | No       |

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

##### Work In Progress (Priority)
* Major code clean up (Almost a complete rewrite!! This project was solely academic at first hence the 'scripty' nature of certain code segments)
* Tidy up and reintegrate unit tests
* Improve PDNS enrichment I/O query performance (on datasets > 250,000 records)
* Automate NVD database updating
* Implement automated task scheduling
* Complete user validation

##### Future Features 
* Implement GreyNoise support
* Integrate the concept of workspaces, similar to Kibana
* Dockerize project

Open to additional feature requests.


**Please note I am by NO means a software developer, so feel free to suggest improvements and changes!** 😊

## License
[GNU V3](https://github.com/LA-Shill/Informant/blob/master/LICENSE)
