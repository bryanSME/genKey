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

def create_self_signed_cert(cert_dir, container_type="pem", keysize=4096, passphrase=None):
    '''
    * create keypair
    * sha512 faster than sha256 on 64bit machines
    * only RSA and DSA are supported
    
    '''
    
    if not exists(join(cert_dir, CERT_FILE))\
            or not exists(join(cert_dir, KEY_FILE)):
            
        #create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, keysize)
        
        # create self-signed cert
        cert = crypto.X509()
        cert.get_subject().C = "US"
        cert.get_subject().ST = "ALIBAMA"
        cert.get_subject().L = "ALIBAMA"
        cert.get_subject().O = "test company"
        cert.get_subject().OU = "uptime"
        cert.get_subject().CN = gethostname()
        cert.set_serial_number(1000)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(k)
        cert.sign(k, 'sha512')
        
        if container_type == "pem":
            ''' TO PEM '''
            crt = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            key = crypto.dump_privatekey(crypto.FILETYPE_PEM, k)
            pem = crt + key
            open("keypair.pem", "wb").write(pem) 
            #open(join(cert_dir, CERT_FILE), "wb").write(crt)
            #open(join(cert_dir, KEY_FILE), "wb").write(key)

        elif container_type == "p12":        
            ''' TO P12 '''
            p12 = crypto.PKCS12()
            p12.set_certificate(cert)
            p12.set_privatekey(k)
            if passphrase != None:
                open(str(gethostname()) + ".p12", "wb").write(
                        p12.export(passphrase=passphrase))
            else:
                open(str(gethostname()) + ".p12", "wb").write(
                        p12.export())
                        
        return

                
if __name__ == "__main__":
    
    pw = raw_input("enter your new cert password and press enter (leave blank for no password):")
    if pw == "":
        pw = None
    create_self_signed_cert(".", container_type="p12", passphrase=pw)
    
    print "Done!"
