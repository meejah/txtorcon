
##
## wrapper for GeoIP since the API for city vs. country is different.
##

import os
import shutil
import GeoIP
import socket
import subprocess

try:
    import psutil
    process_factory = psutil.Process
except ImportError:
    process_factory = int
process_factory = int

city = None
country = None
asn = None

try:
    city = GeoIP.open("/usr/share/GeoIP/GeoLiteCity.dat", GeoIP.GEOIP_STANDARD)
except:
    pass

try:
    asn = GeoIP.open("/usr/share/GeoIP/GeoIPASNum.dat", GeoIP.GEOIP_STANDARD)
except:
    pass

country = GeoIP.new(GeoIP.GEOIP_STANDARD)

def delete_file_or_tree(*args):
    """"
    For every path in args, try to delete is as a file or a directory tree
    """
    
    for f in args:
        try:
            os.unlink(f)
        except OSError:
            shutil.rmtree(f, ignore_errors=True)
                
def ip_from_int(self, ip):
        """ Convert long int back to dotted quad string """
        return socket.inet_ntoa(struct.pack('>I', ip))

def process_from_address(addr, port, torstate):
    """
    Determines the PID from the address/port provided by using lsof
    and returns a psutil.Process object (or None). In the special case
    the addr is '(Tor_internal)' then Process having the PID of the
    Tor process (as gotten from the torstate object) is returned.

    If psutil isn't installed, the PIDs are returned instead of
    psutil.Process instances.    
    """

    if addr == None:
        return None

    if "(tor_internal)" == addr.lower():
        return process_factory(torstate.tor_pid)

    proc = subprocess.Popen(['lsof','-i','4tcp@%s:%s' % (addr,port)],
                            stdout = subprocess.PIPE)
    (stdout, stderr) = proc.communicate()
    lines = stdout.split('\n')
    if len(lines) > 1:
        pid = int(lines[1].split()[1])
        return process_factory(int(pid))

    return None

    

##
## classes
##

class NetLocation:
    """
    Represents the location of an IP address, either city or country
    level resolution depending on what GeoIP database was loaded. If
    the ASN database is available you get that also.
    """

    def __init__(self, ipaddr):
        "ipaddr should be a dotted-quad"
        self.ip = ipaddr
        self.latlng = (None, None)
        self.countrycode = None
        self.city = None
        self.asn = None
        
        if city:
            r = city.record_by_addr(self.ip)
            if r is not None:
                self.countrycode = r['country_code']
                self.latlng = (r['latitude'], r['longitude'])
                self.city = (r['city'], r['region'])
            
        else:
            self.countrycode = country.country_code_by_addr(ipaddr)
            
        if asn:
            self.asn = asn.org_by_addr(self.ip)
                
