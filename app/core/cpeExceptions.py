# !/usr/bin/env python
# Name:     cpeExceptions.py
# By:       LA-Shill
# Date:     11.01.2021
# Version   0.1
# -----------------------------------------------

# ssh = ['OpenBSD', 'Dropbear', 'wolfSSH', 'Lsh', 'Bitvise', 'CopSSH', 'FreeSSHd', 'OpenSSH']
# web = ['Apache']

def exceptions(manufacturer, vendor, product, version):
    jStr = ':'
    cpeArray = ['cpe:2.3', 'a', manufacturer, product, version, '*','*', '*', '*', '*', '*', '*']

    """ SSH CHECKS """

    if vendor == 'openssh' or manufacturer == 'openssh' or product == 'openssh':
        pl = '*'
        # Check for package in version number
        if any(c.isalpha() for c in version):
            pl = (version[version.find('p'):])
            version = (version[:version.find('p')])

            # Further check to get rid of Ubuntu junk from pl (BinaryEdge results)
            if 'ubuntu' in pl:
                pl=pl[:2]

        cpeArray[2] = 'openbsd'
        cpeArray[3] = 'openssh'
        cpeArray[4] = version
        cpeArray[5] = pl
    
    """ WEB SERVER CHECKS """
    if ('nginx' in vendor or 'nginx' in manufacturer or 'nginx' in product):
        cpeArray[2] = 'nginx'
        cpeArray[3] = 'nginx'

    if (('microsoft' in vendor or 'microsoft' in manufacturer or 'microsoft' in product) and ('iis' in vendor or 'iis' in manufacturer or 'iis' in product)):
        cpeArray[2] = 'microsoft'
        cpeArray[3] = 'internet_information_server'
    if (('apache' in vendor or 'apache' in manufacturer or 'apache' in product) and ('httpd' in vendor or 'httpd' in manufacturer or 'httpd' in product)):
        cpeArray[2] = 'apache'
        cpeArray[3] = 'http_server'
    if vendor == 'httpapi' or manufacturer == 'httpapi' or product == 'httpapi' or 'httpapi' in product:
        cpeArray[2] = 'wampserver'
        cpeArray[3] = 'wampserver'
    if vendor == 'lighttpd' or manufacturer == 'lighttpd' or product == 'lighttpd':
        cpeArray[2] = 'lighttpd'
        cpeArray[3] = 'lighttpd'
    if vendor == 'sendmail' or manufacturer == 'sendmail' or product == 'sendmail':
        cpeArray[2] = 'sendmail'
        cpeArray[3] = 'sendmail'
    if vendor == 'postfix' or manufacturer == 'postfix' or product == 'postfix':
        cpeArray[2] = 'postfix'
        cpeArray[3] = 'postfix'
    cpeString = jStr.join(cpeArray).lower()
     
    return cpeString