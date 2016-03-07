# -*- coding: utf-8 -*-
"""
Created on Mon Mar 07 07:11:11 2016

@author: bryan
"""

from OpenSSL import crypto, SSL
from socket import gethostname
from pprint import pprint
from time import gmtime, mktime
from os.path import exists, join

CERT_FILE = "myapp.crt"
KEY_FILE = "myapp.key"

def create_self_signed_cert(cert_dir):
    '''
    if datacard.crt and datacard.key don't exsist, create them
    '''
    
    if not exists(join(cert_dir, CERT_FILE))\
            or not exists(join(cert_dir, KEY_FILE)):
            
        #create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 4096)
        
        # create self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "VIRGINIA"
        cert.get_subject().L = "VIRGINIA"
        cert.get_subject().O = "test company"
        cert.get_subject().OU = "uptime"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha1')
        
        open(join(cert_dir, CERT_FILE), "wt").write(
                crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        open(join(cert_dir, KEY_FILE), "wt").write(
                crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

                
if __name__ == "__main__":
    create_self_signed_cert(".")