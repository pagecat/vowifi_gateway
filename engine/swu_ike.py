import serial
import struct
import socket
import random
import time
import select
import sys
import os
import fcntl
import subprocess
import multiprocessing
import requests

from optparse import OptionParser
from binascii import hexlify, unhexlify

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from Crypto.Cipher import AES
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from smartcard.System import readers
from smartcard.util import toHexString,toBytes
try:
    from smartcard.scard import SCardBeginTransaction, SCardEndTransaction, SCARD_LEAVE_CARD
except Exception:                     # pragma: no cover
    SCardBeginTransaction = SCardEndTransaction = None
    SCARD_LEAVE_CARD = 0

from CryptoMobile.Milenage import Milenage

from card.USIM import *

requests.packages.urllib3.disable_warnings()

# =============================================================================================
# VoWiFi engine integration (headless daemon glue). These helpers let swu_ike.py run as the
# engine's tunnel process in place of strongSwan: emit tunnel state + P-CSCF to the run dir,
# notify the manager, and keep a readable IKE log the control plane can classify.
# =============================================================================================
import json as _json
import signal as _signal

SWU_RUNDIR = os.environ.get("VOWIFI_RUNDIR", "/run/vowifi")
SWU_IFACE = os.environ.get("SWU_IFACE", "ipsec0")          # tun device name (pjsip binds this)
SWU_NOTIFY = os.environ.get("SWU_NOTIFY", "/usr/local/bin/notify.py")
SWU_ASSIGN_IPV6_GLOBAL = os.environ.get("SWU_ASSIGN_IPV6_GLOBAL", "1") not in ("0", "", "no")
SWU_WRITE_RESOLV = os.environ.get("SWU_WRITE_RESOLV", "0") not in ("0", "", "no")


def swu_log(msg):
    """Emit a tagged status line. swu_ike's stdout is redirected to run/charon.log by the
    entrypoint, so a plain print() lands in the IKE log (which control-plane classify_ike /
    charon_log read) without intermixing into Asterisk's console. Falls back to appending
    directly only if stdout isn't already the IKE log (e.g. the netns probe run)."""
    line = "[swu_ike] " + str(msg)
    print(line, flush=True)


def swu_write_status(state, **extra):
    try:
        os.makedirs(SWU_RUNDIR, exist_ok=True)
        data = {"state": state, "ts": int(time.time())}
        data.update(extra)
        tmp = os.path.join(SWU_RUNDIR, "swu_status.json.tmp")
        with open(tmp, "w") as f:
            _json.dump(data, f)
        os.replace(tmp, os.path.join(SWU_RUNDIR, "swu_status.json"))
    except Exception as e:
        print("[swu_ike] status write failed: %r" % e, flush=True)


def swu_write_pcscf(addr):
    try:
        os.makedirs(SWU_RUNDIR, exist_ok=True)
        with open(os.path.join(SWU_RUNDIR, "pcscf"), "w") as f:
            f.write(addr or "")
    except Exception:
        pass


def swu_notify(event, arg=None):
    try:
        cmd = ["python3", SWU_NOTIFY, event]
        if arg:
            cmd.append(arg)
        subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass


def swu_apply_pcscf(addr):
    """Re-render pjsip.conf for a (possibly new) P-CSCF and reload Asterisk, but only when the
    P-CSCF actually changed. The ePDG can hand out a DIFFERENT P-CSCF on every (re)connect /
    reauth; pjsip's type=identify/type=resolve are pinned to the P-CSCF IP, so a stale value
    means inbound INVITEs from the new P-CSCF don't match (calls/SMS fail) and outbound routing
    is wrong. This keeps them in sync on every reconnect, not just the first bring-up."""
    if not addr:
        return
    last = None
    try:
        with open(os.path.join(SWU_RUNDIR, "pcscf.applied")) as f:
            last = f.read().strip()
    except Exception:
        last = None
    if last == addr:
        return
    render = os.environ.get("SWU_RENDER", "/usr/local/bin/render.py")
    if not os.path.exists(render):
        return
    try:
        swu_log("P-CSCF changed (%s -> %s); re-rendering pjsip + reloading Asterisk" % (last, addr))
        subprocess.call(["python3", render], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        # Reload just the parts affected by the P-CSCF change. res_pjsip reload re-reads
        # pjsip.conf (identify/resolve/registration/endpoint) without dropping the tunnel.
        subprocess.call(["asterisk", "-rx", "module reload res_pjsip.so"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(["asterisk", "-rx", "pjsip send register volte_ims"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with open(os.path.join(SWU_RUNDIR, "pcscf.applied"), "w") as f:
            f.write(addr)
    except Exception as e:
        swu_log("pcscf apply failed: %r" % e)


'''

Ike Process

IPsec_encoder (receives data from tunnel interface -> encrypts and sends it towards the server/epdg)

IPsec_decoder (receives encrypted data from server/epdg -> decypts it and sends it to the tunnel interface)

'''

INTER_PROCESS_CREATE_SA = 1
INTER_PROCESS_UPDATE_SA = 2
INTER_PROCESS_DELETE_SA = 3
INTER_PROCESS_IKE       = 4

INTER_PROCESS_IE_ENCR_ALG    = 1
INTER_PROCESS_IE_INTEG_ALG   = 2
INTER_PROCESS_IE_ENCR_KEY    = 3
INTER_PROCESS_IE_INTEG_KEY   = 4
INTER_PROCESS_IE_SPI_INIT    = 5
INTER_PROCESS_IE_SPI_RESP    = 6
INTER_PROCESS_IE_IKE_MESSAGE = 7


#DEFAULTs

DEFAULT_IKE_PORT = 500
DEFAULT_IKE_NAT_TRAVERSAL_PORT = 4500

DEFAULT_SERVER = '1.2.3.4'

DEFAULT_COM = '/dev/ttyUSB2'
DEFAULT_IMSI = '123456012345678'
DEFAULT_MCC = '123'
DEFAULT_MNC = '456'
DEFAULT_APN = 'internet'
DEFAULT_TIMEOUT_UDP = 2
#DEFAULT_TIMEOUT_UDP_NAT_TRANSVERSAL = 2

DEFAULT_CK = '0123456789ABCDEF0123456789ABCDEF'
DEFAULT_IK = '0123456789ABCDEF0123456789ABCDEF'
DEFAULT_RES = '0123456789ABCDEF'


# IMEI (15 digits) and IMEISV (16 digits) - used in DEVICE_IDENTITY notify response
IMEI                                    = '123456789012347'   # 15 digits. The last digit (7) is the checksum digit.
IMEISV                                  = '1234567890123456'  # 16 digits


NONE = 0

#IKEv2 Payload Types
SA =      33
KE =      34
IDI =     35
IDR =     36 
CERT =    37
CERTREQ = 38
AUTH =    39
NINR =    40
N =       41
D =       42
V =       43
TSI =     44
TSR =     45
SK =      46
CP =      47 
EAP =     48

#IKEv2 Exchange Types
IKE_SA_INIT =     34
IKE_AUTH =        35
CREATE_CHILD_SA = 36
INFORMATIONAL =   37

RESERVED = 0
IKE = 1
AH =  2
ESP = 3   

#Transform Type Values
ENCR = 1
PRF = 2
INTEG = 3
D_H = 4
ESN = 5


#Transform Type 1 - Encryption Algorithm Transform IDs
ENCR_DES_IV64 =    1
ENCR_DES=          2
ENCR_3DES =        3
ENCR_RC5 =         4
ENCR_IDEA =        5
ENCR_CAST =        6
ENCR_BLOWFISH =    7
ENCR_3IDEA =       8
ENCR_DES_IV32 =    9
ENCR_NULL =       11 #Not allowed
ENCR_AES_CBC =    12
ENCR_AES_CTR =    13
ENCR_AES_CCM_8 =  14
ENCR_AES_CCM_12 = 15
ENCR_AES_CCM_16 = 16
ENCR_AES_GCM_8 =  18
ENCR_AES_GCM_12 = 19
ENCR_AES_GCM_16 = 20

#Transform Type 2 - Pseudorandom Function Transform IDs
PRF_HMAC_MD5 =          1
PRF_HMAC_SHA1 =         2
PRF_HMAC_TIGER =        3
PRF_AES128_XCBC =       4
PRF_HMAC_SHA2_256 =     5
PRF_HMAC_SHA2_384 =     6
PRF_HMAC_SHA2_512 =     7
PRF_AES128_CMAC =       8

#Transform Type 3 - Integrity Algorithm Transform IDs
NONE =                      0
AUTH_HMAC_MD5_96 =	        1
AUTH_HMAC_SHA1_96 =         2
AUTH_DES_MAC =	            3
AUTH_KPDK_MD5 =             4
AUTH_AES_XCBC_96 =          5
AUTH_HMAC_MD5_128 =         6
AUTH_HMAC_SHA1_160 =        7
AUTH_AES_CMAC_96 =          8
AUTH_AES_128_GMAC =         9
AUTH_AES_192_GMAC =        10
AUTH_AES_256_GMAC =        11
AUTH_HMAC_SHA2_256_128 =   12
AUTH_HMAC_SHA2_384_192 =   13
AUTH_HMAC_SHA2_512_256 =   14

#Transform Type 4 - Diffie-Hellman Group Transform IDs
MODP_768_bit =          1
MODP_1024_bit =         2
MODP_1536_bit =         5
MODP_2048_bit =        14
MODP_3072_bit =        15
MODP_4096_bit =        16
MODP_6144_bit =        17
MODP_8192_bit =        18


ESN_NO_ESN = 0
ESN_ESN =    1

TLV = 0
TV =  1

#IKEv2 Transform Attribute Types
KEY_LENGTH = (14, TV)


#states
OK =                            0
TIMEOUT =                       1
REPEAT_STATE =                  2
DECODING_ERROR =                3
MANDATORY_INFORMATION_MISSING = 4
OTHER_ERROR =                   5
REPEAT_STATE_COOKIE =           6


#IKEv2 Notify Message Types - Error Types
UNSUPPORTED_CRITICAL_PAYLOAD            =     1
INVALID_IKE_SPI                         =     4
INVALID_MAJOR_VERSION                   =     5
INVALID_SYNTAX                          =     7
INVALID_MESSAGE_ID                      =     9
INVALID_SPI                             =    11
NO_PROPOSAL_CHOSEN                      =    14
INVALID_KE_PAYLOAD                      =    17
AUTHENTICATION_FAILED                   =    24
SINGLE_PAIR_REQUIRED                    =    34
NO_ADDITIONAL_SAS                       =    35
INTERNAL_ADDRESS_FAILURE                =    36
FAILED_CP_REQUIRED                      =    37
TS_UNACCEPTABLE                         =    38
INVALID_SELECTORS                       =    39
TEMPORARY_FAILURE                       =    43
CHILD_SA_NOT_FOUND                      =    44
# from 24.302                                        
PDN_CONNECTION_REJECTION                =  8192
MAX_CONNECTION_REACHED                  =  8193
SEMANTIC_ERROR_IN_THE_TFT_OPERATION     =  8241
SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION  =  8242
SEMANTIC_ERRORS_IN_PACKET_FILTERS       =  8244
SYNTACTICAL_ERRORS_IN_PACKET_FILTERS    =  8245
NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED      =  9000
USER_UNKNOWN                            =  9001
NO_APN_SUBSCRIPTION                     =  9002
AUTHORIZATION_REJECTED                  =  9003
ILLEGAL_ME                              =  9006
NETWORK_FAILURE                         = 10500
RAT_TYPE_NOT_ALLOWED                    = 11001
IMEI_NOT_ACCEPTED                       = 11005
PLMN_NOT_ALLOWED                        = 11011
UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED = 11055

#IKEv2 Notify Message Types - Status Types
INITIAL_CONTACT                         = 16384
SET_WINDOW_SIZE                         = 16385
ADDITIONAL_TS_POSSIBLE                  = 16386
IPCOMP_SUPPORTED                        = 16387      
NAT_DETECTION_SOURCE_IP                 = 16388      
NAT_DETECTION_DESTINATION_IP            = 16389
COOKIE                                  = 16390
USE_TRANSPORT_MODE                      = 16391
HTTP_CERT_LOOKUP_SUPPORTED              = 16392
REKEY_SA                                = 16393
ESP_TFC_PADDING_NOT_SUPPORTED           = 16394
NON_FIRST_FRAGMENTS_ALSO                = 16395

EAP_ONLY_AUTHENTICATION                 = 16417
# from 24.302                                        
REACTIVATION_REQUESTED_CAUSE            = 40961
BACKOFF_TIMER                           = 41041
PDN_TYPE_IPv4_ONLY_ALLOWED              = 41050
PDN_TYPE_IPv6_ONLY_ALLOWED              = 41051
DEVICE_IDENTITY                         = 41101
EMERGENCY_SUPPORT                       = 41112
EMERGENCY_CALL_NUMBERS                  = 41134
NBIFOM_GENERIC_CONTAINER                = 41288
P_CSCF_RESELECTION_SUPPORT              = 41304
PTI                                     = 41501
IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY  = 42011
EPS_QOS                                 = 42014
EXTENDED_EPS_QOS                        = 42015
TFT                                     = 42017
MODIFIED_BEARER                         = 42020
APN_AMBR                                = 42094
EXTENDED_APN_AMBR                       = 42095
N1_MODE_CAPABILITY                      = 51015
N1_MODE_INFORMATION                     = 51115
N1_MODE_S_NSSAI_PLMN_ID                 = 52216
DNS_SRV_SEC_INFO_IND                    = 52301
DNS_SRV_SEC_INFO                        = 52302
ATSSS_REQUEST                           = 52331
ATSSS_RESPONSE                          = 52332
HPA_INFO                                = 55911

# Reverse lookup: IKEv2 Notify Message Type value -> name, for decode/logging of received
# Notify payloads and for responding correctly to ePDG requests (3GPP TS 24.302 clause 8.1.2).
# Covers RFC 7296 status/error notifies plus the FULL 3GPP private ranges:
#   Table 8.1.2.2-1 (Private Error Types)  and  Table 8.1.2.3-1 (Private Status Types).
# Only genuine Notify Message Types are listed (so protocol-ID and transform constants that
# happen to share integer values are never confused for notifies).
NOTIFY_TYPE_NAMES = {
    # ---- RFC 7296 error types (< 16384) ----
    1: "UNSUPPORTED_CRITICAL_PAYLOAD", 4: "INVALID_IKE_SPI", 5: "INVALID_MAJOR_VERSION",
    7: "INVALID_SYNTAX", 9: "INVALID_MESSAGE_ID", 11: "INVALID_SPI",
    14: "NO_PROPOSAL_CHOSEN", 17: "INVALID_KE_PAYLOAD", 24: "AUTHENTICATION_FAILED",
    34: "SINGLE_PAIR_REQUIRED", 35: "NO_ADDITIONAL_SAS", 36: "INTERNAL_ADDRESS_FAILURE",
    37: "FAILED_CP_REQUIRED", 38: "TS_UNACCEPTABLE", 39: "INVALID_SELECTORS",
    40: "UNACCEPTABLE_ADDRESSES", 41: "UNEXPECTED_NAT_DETECTED", 43: "TEMPORARY_FAILURE",
    44: "CHILD_SA_NOT_FOUND",
    # ---- 3GPP TS 24.302 Table 8.1.2.2-1: Private Error Types ----
    8192: "PDN_CONNECTION_REJECTION", 8193: "MAX_CONNECTION_REACHED",
    8241: "SEMANTIC_ERROR_IN_THE_TFT_OPERATION",
    8242: "SYNTACTICAL_ERROR_IN_THE_TFT_OPERATION",
    8244: "SEMANTIC_ERRORS_IN_PACKET_FILTERS",
    8245: "SYNTACTICAL_ERRORS_IN_PACKET_FILTERS",
    9000: "NON_3GPP_ACCESS_TO_EPC_NOT_ALLOWED", 9001: "USER_UNKNOWN",
    9002: "NO_APN_SUBSCRIPTION", 9003: "AUTHORIZATION_REJECTED", 9006: "ILLEGAL_ME",
    10500: "NETWORK_FAILURE", 11001: "RAT_TYPE_NOT_ALLOWED", 11005: "IMEI_NOT_ACCEPTED",
    11011: "PLMN_NOT_ALLOWED", 11055: "UNAUTHENTICATED_EMERGENCY_NOT_SUPPORTED",
    # ---- RFC 7296 status types (>= 16384) ----
    16384: "INITIAL_CONTACT", 16385: "SET_WINDOW_SIZE", 16386: "ADDITIONAL_TS_POSSIBLE",
    16387: "IPCOMP_SUPPORTED", 16388: "NAT_DETECTION_SOURCE_IP",
    16389: "NAT_DETECTION_DESTINATION_IP", 16390: "COOKIE", 16391: "USE_TRANSPORT_MODE",
    16392: "HTTP_CERT_LOOKUP_SUPPORTED", 16393: "REKEY_SA",
    16394: "ESP_TFC_PADDING_NOT_SUPPORTED", 16395: "NON_FIRST_FRAGMENTS_ALSO",
    16417: "EAP_ONLY_AUTHENTICATION",
    # ---- 3GPP TS 24.302 Table 8.1.2.3-1: Private Status Types ----
    40961: "REACTIVATION_REQUESTED_CAUSE", 41041: "BACKOFF_TIMER",
    41050: "PDN_TYPE_IPv4_ONLY_ALLOWED", 41051: "PDN_TYPE_IPv6_ONLY_ALLOWED",
    41101: "DEVICE_IDENTITY", 41112: "EMERGENCY_SUPPORT",
    41134: "EMERGENCY_CALL_NUMBERS", 41288: "NBIFOM_GENERIC_CONTAINER",
    41304: "P_CSCF_RESELECTION_SUPPORT", 41501: "PTI",
    42011: "IKEV2_MULTIPLE_BEARER_PDN_CONNECTIVITY", 42014: "EPS_QOS",
    42015: "EXTENDED_EPS_QOS", 42017: "TFT", 42020: "MODIFIED_BEARER",
    42094: "APN_AMBR", 42095: "EXTENDED_APN_AMBR", 51015: "N1_MODE_CAPABILITY",
    51115: "N1_MODE_INFORMATION", 52216: "N1_MODE_S_NSSAI_PLMN_ID",
    52301: "DNS_SRV_SEC_INFO_IND", 52302: "DNS_SRV_SEC_INFO",
    52331: "ATSSS_REQUEST", 52332: "ATSSS_RESPONSE", 55911: "HPA_INFO",
}

# Friendly, human-readable descriptions for the 3GPP TS 24.302 private Notify types (Tables
# 8.1.2.2-1 and 8.1.2.3-1). Used to render errors/status in the IKE log so operators do not
# have to look up the numeric code. Keyed by Notify Message Type value.
NOTIFY_DESCRIPTIONS = {
    # ---- Private Error Types (Table 8.1.2.2-1) ----
    8192: "PDN connection (for the IP address in the notify data) was rejected by the network",
    8193: "Max PDN connections for this APN reached; no more can be established (first-conn "
          "rejection means the APN is not allowed for this UE)",
    8241: "Requested service rejected: semantic error in the TFT operation in the request",
    8242: "Requested service rejected: syntactical error in the TFT operation in the request",
    8244: "Requested service rejected: semantic error in the packet filter(s) in the request",
    8245: "Requested service rejected: syntactical error in the packet filter(s) in the request",
    9000: "Non-3GPP access to EPC not allowed (no non-3GPP subscription / policy) "
          "[DIAMETER_ERROR_USER_NO_NON_3GPP_SUBSCRIPTION]",
    9001: "User unknown - the IMSI is not known to the network [DIAMETER_ERROR_USER_UNKNOWN]",
    9002: "No APN subscription - requested APN not in the user profile "
          "[DIAMETER_ERROR_USER_NO_APN_SUBSCRIPTION]",
    9003: "Authorization rejected - user barred from non-3GPP access or this APN "
          "[DIAMETER_AUTHORIZATION_REJECTED]",
    9006: "Illegal ME - the mobile equipment is not accepted by the network "
          "[DIAMETER_ERROR_ILLEGAL_EQUIPMENT]",
    10500: "Network failure - the requested procedure could not be completed "
           "[DIAMETER_ERROR_UNABLE_TO_COMPLY]",
    11001: "RAT type not allowed - access type is restricted for this user "
           "[DIAMETER_RAT_TYPE_NOT_ALLOWED]",
    11005: "IMEI not accepted - emergency request using an IMEI was rejected",
    11011: "PLMN not allowed - roaming/PLMN filtering rejected the request "
           "[DIAMETER_ERROR_ROAMING_NOT_ALLOWED]",
    11055: "Unauthenticated emergency not supported - emergency with unauthenticated IMSI "
           "rejected (auth failed / cannot proceed at AAA)",
    # ---- Private Status Types (Table 8.1.2.3-1) ----
    40961: "Reactivation requested - the IPsec tunnel was released; UE should re-establish it "
           "for the same PDN connection",
    41041: "Backoff timer - network-supplied backoff timer value (GPRS timer 3)",
    41050: "Only PDN type IPv4 is allowed for the requested PDN connectivity",
    41051: "Only PDN type IPv6 is allowed for the requested PDN connectivity",
    41101: "Device identity - the ePDG requests (or the UE supplies) the IMEI/IMEISV",
    41112: "Emergency support - the ePDG supports emergency service",
    41134: "Emergency call numbers - local emergency numbers provided by the ePDG",
    41288: "NBIFOM generic container",
    41304: "P-CSCF reselection support (P-CSCF restoration extension for untrusted WLAN)",
    41501: "PTI - procedure transaction identity for an ePDG-initiated modification",
    42011: "IKEv2 multiple bearer PDN connectivity support",
    42014: "EPS QoS",
    42015: "Extended EPS QoS",
    42017: "TFT (traffic flow template)",
    42020: "Modified bearer - sender's ESP SPI",
    42094: "APN-AMBR",
    42095: "Extended APN-AMBR",
    51015: "N1 mode capability / PDU session ID",
    51115: "N1 mode information (S-NSSAI)",
    52216: "N1 mode S-NSSAI PLMN ID",
    52301: "DNS server security info indication",
    52302: "DNS server security info",
    52331: "ATSSS request parameters",
    52332: "ATSSS response parameters",
    55911: "High priority access info",
}

def notify_name(value):
    return NOTIFY_TYPE_NAMES.get(value, "UNKNOWN")

def notify_describe(value):
    """Return a human-friendly one-line description for a Notify Message Type, or '' if none."""
    return NOTIFY_DESCRIPTIONS.get(value, "")

#IKEv2 Authenticaton Method
RSA_DIGITAL_SIGNATURE             = 1
SHARED_KEY_MESSAGE_INTEGRITY_CODE = 2
DSS_DIGITAL_SIGNATURE             = 3

#IKEv2 Traffic Selector Types
TS_IPV4_ADDR_RANGE = 7
TS_IPV6_ADDR_RANGE = 8

#IP protocol_id
ANY =   0
TCP =   6
UDP =  17
ICMP =  1
ESP_PROTOCOL = 50

NAT_TRAVERSAL = 4500

#IKEv2 Configuration Payload CFG Types
CFG_REQUEST =       1
CFG_REPLY =         2
CFG_SET =           3
CFG_ACK =           4

# IKEv2 Configuration Payload Attribute Types (num, length) None = more
INTERNAL_IP4_ADDRESS	           = 1
INTERNAL_IP4_NETMASK	           = 2
INTERNAL_IP4_DNS	               = 3
INTERNAL_IP4_NBNS	               = 4
INTERNAL_IP4_DHCP		           = 6
APPLICATION_VERSION		           = 7
INTERNAL_IP6_ADDRESS	           = 8
INTERNAL_IP6_DNS	               = 10
INTERNAL_IP6_DHCP	               = 12
INTERNAL_IP4_SUBNET	               = 13
SUPPORTED_ATTRIBUTES	           = 14
INTERNAL_IP6_SUBNET	               = 15
MIP6_HOME_PREFIX	               = 16
INTERNAL_IP6_LINK	               = 17
INTERNAL_IP6_PREFIX	               = 18
HOME_AGENT_ADDRESS	               = 19
P_CSCF_IP4_ADDRESS	               = 20
P_CSCF_IP6_ADDRESS	               = 21
FTT_KAT		                       = 22
EXTERNAL_SOURCE_IP4_NAT_INFO       = 23
TIMEOUT_PERIOD_FOR_LIVENESS_CHECK  = 24
INTERNAL_DNS_DOMAIN	               = 25
INTERNAL_DNSSEC_TA                 = 26

#IKEv2 Identification Payload ID Types
ID_IPV4_ADDR     = 1
ID_FQDN	         = 2
ID_RFC822_ADDR	 = 3
ID_IPV6_ADDR	 = 5
ID_DER_ASN1_DN	 = 9
ID_DER_ASN1_GN	 = 10
ID_KEY_ID	     = 11
ID_FC_NAME	     = 12
ID_NULL	         = 13




#EAP COde type
EAP_REQUEST  = 1
EAP_RESPONSE = 2
EAP_SUCCESS  = 3
EAP_FAILURE  = 4

#IANA EAP Type
EAP_AKA = 23

#EAP-AKA/EAP-SIM Subtypes:
AKA_Challenge = 1
AKA_Authentication_Reject = 2
AKA_Synchronization_Failure = 4
AKA_Identity = 5
SIM_Start = 10
SIM_Challenge = 11
AKA_Notification = 12
SIM_Notification = 12
AKA_Reauthentication = 13
SIM_Reauthentication = 13
AKA_Client_Error = 14
SIM_Client_Error = 14

#EAP-AKA/EAP-SIM Atrributes:
AT_RAND = 1
AT_AUTN = 2
AT_RES = 3
AT_AUTS = 4
AT_PADDING = 6
AT_NONCE_MT = 7
AT_PERMANENT_ID_REQ = 10
AT_MAC = 11
AT_NOTIFICATION = 12
AT_ANY_ID_REQ = 13
AT_IDENTITY = 14
AT_VERSION_LIST = 15
AT_SELECTED_VERSION = 16
AT_FULLAUTH_ID_REQ = 17
AT_COUNTER = 19
AT_COUNTER_TOO_SMALL = 20
AT_NONCE_S = 21
AT_CLIENT_ERROR_CODE = 22
AT_IV = 129
AT_ENCR_DATA = 130
AT_NEXT_PSEUDONYM = 132
AT_NEXT_REAUTH_ID = 133
AT_CHECKCODE = 134
AT_RESULT_IND = 135


# Role
ROLE_INITIATOR = 1
ROLE_RESPONDER = 0


class swu():

    def __init__(self, source_address,epdg_address,apn,modem,default_gateway,mcc,mnc,imsi,ki,op,opc,netns,sqn):
        self.source_address = source_address
        self.epdg_address = epdg_address
        self.apn = apn
        self.com_port = modem
        self.default_gateway = default_gateway
        self.mcc = mcc
        self.mnc = mnc
        self.imsi = imsi 
        
        self.ki = ki
        self.op = op
        self.opc = opc
        
        self.netns_name = netns
        self.sqn = sqn
        
        self.set_variables()
        self.set_udp() # default
        self.create_socket(self.client_address)
        self.create_socket_nat(self.client_address_nat)
        self.create_socket_esp(self.client_address_esp)        
        self.userplane_mode = ESP_PROTOCOL
        
        self.sk_ENCR_NULL_pad_length = 0 #[0 or 1 byte] SK payload is not definied in RFC for IKEv2. Some vendors don't use pad length byte, others use.

        
    def set_variables(self):
        self.port = DEFAULT_IKE_PORT
        self.port_nat = DEFAULT_IKE_NAT_TRAVERSAL_PORT
        self.client_address = (self.source_address,self.port)
        self.client_address_nat = (self.source_address,self.port_nat) 
        self.client_address_esp = (self.source_address,0)         
        self.timeout = DEFAULT_TIMEOUT_UDP
        self.state = 0
        self.server_address = (self.epdg_address, self.port)
        self.server_address_nat = (self.epdg_address, self.port_nat)
        self.server_address_esp = (self.epdg_address, 0)        
        self.message_id_request = 0
        self.message_id_responses = 0

        self.role = ROLE_INITIATOR
        self.old_ike_message_received = False        
        self.ike_spi_initiator_old = None
        self.ike_spi_responder_old = None
        self.next_reauth_id = None
        
        self.check_nat = True
        self.device_identity_requested = False
        self.device_identity_type = None
        # Per-instance IMEI/IMEISV for the ePDG DEVICE_IDENTITY response. Default to the module
        # constants (upstream behaviour) until set_device_identity() overrides them.
        self.imei = IMEI
        self.imeisv = IMEISV

        self.set_identification(IDI,ID_RFC822_ADDR,'0' + self.imsi + '@nai.epc.mnc' + self.mnc + '.mcc' + self.mcc + '.3gppnetwork.org')
#       self.set_identification(IDR,ID_FQDN, self.apn + '.apn.epc.mnc' + self.mnc + '.mcc' + self.mcc + '.3gppnetwork.org')
        self.set_identification(IDR,ID_FQDN, self.apn)
        
        self.ike_decoded_header = {}
        self.decodable_payloads = [
            SA,
            KE,
            IDI,
            IDR,
            CERT,
            CERTREQ,
            AUTH,
            NINR,
            N,
            D,
            V,
            TSI,
            TSR,
            SK,
            CP,
            EAP
        ]
      
        self.iana_diffie_hellman = {
            MODP_768_bit:   768,
            MODP_1024_bit: 1024,
            MODP_1536_bit: 1536,
            MODP_2048_bit: 2048,
            MODP_3072_bit: 3072,
            MODP_4096_bit: 4096,
            MODP_6144_bit: 6144,
            MODP_8192_bit: 8192 
        }
        self.prf_function = {
            PRF_HMAC_MD5 :        hashes.MD5(),
            PRF_HMAC_SHA1 :       hashes.SHA1(),    
            #PRF_HMAC_TIGER :        3
            #PRF_AES128_XCBC :       4
            PRF_HMAC_SHA2_256 :   hashes.SHA256(),
            PRF_HMAC_SHA2_384 :   hashes.SHA384(),
            PRF_HMAC_SHA2_512 :   hashes.SHA512()
            #PRF_AES128_CMAC :       8 
        }
        self.prf_key_len_bytes = {
            PRF_HMAC_MD5 :          16,
            PRF_HMAC_SHA1 :         20,
            #PRF_HMAC_TIGER :        -,
            PRF_AES128_XCBC :       16,
            PRF_HMAC_SHA2_256 :     32,
            PRF_HMAC_SHA2_384 :     48,
            PRF_HMAC_SHA2_512 :     64,
            PRF_AES128_CMAC :       16,
            
        }
        self.integ_function = {        
            NONE :                      None,
            AUTH_HMAC_MD5_96 :	        hashes.MD5(),
            AUTH_HMAC_SHA1_96 :         hashes.SHA1(),
            #AUTH_DES_MAC :	            -,
            #AUTH_KPDK_MD5 :             -,
            #AUTH_AES_XCBC_96 :          16,
            #AUTH_HMAC_MD5_128 :         -,
            #AUTH_HMAC_SHA1_160 :        -,
            #AUTH_AES_CMAC_96 :          -,
            #AUTH_AES_128_GMAC :         16,
            #AUTH_AES_192_GMAC :        24,
            #AUTH_AES_256_GMAC :        32,
            AUTH_HMAC_SHA2_256_128 :   hashes.SHA256(),
            AUTH_HMAC_SHA2_384_192 :   hashes.SHA384(),
            AUTH_HMAC_SHA2_512_256 :   hashes.SHA512()            
        }        
        self.integ_key_len_bytes = {        
            NONE :                      0,
            AUTH_HMAC_MD5_96 :	        16,
            AUTH_HMAC_SHA1_96 :         20,
            #AUTH_DES_MAC :	            -,
            #AUTH_KPDK_MD5 :             -,
            #AUTH_AES_XCBC_96 :          16,
            #AUTH_HMAC_MD5_128 :         -,
            #AUTH_HMAC_SHA1_160 :        -,
            #AUTH_AES_CMAC_96 :          -,
            #AUTH_AES_128_GMAC :         16,
            #AUTH_AES_192_GMAC :        24,
            #AUTH_AES_256_GMAC :        32,
            AUTH_HMAC_SHA2_256_128 :   32,
            AUTH_HMAC_SHA2_384_192 :   48,
            AUTH_HMAC_SHA2_512_256 :   64        
        }
        self.integ_key_truncated_len_bytes = {        
            NONE :                      0,
            AUTH_HMAC_MD5_96 :	        12,
            AUTH_HMAC_SHA1_96 :         12,
            #AUTH_DES_MAC :	            -,
            #AUTH_KPDK_MD5 :             -,
            #AUTH_AES_XCBC_96 :          12,
            #AUTH_HMAC_MD5_128 :         -,
            #AUTH_HMAC_SHA1_160 :        -,
            #AUTH_AES_CMAC_96 :          -,
            #AUTH_AES_128_GMAC :         16?,
            #AUTH_AES_192_GMAC :        24?,
            #AUTH_AES_256_GMAC :        32?,
            AUTH_HMAC_SHA2_256_128 :   16,
            AUTH_HMAC_SHA2_384_192 :   24,
            AUTH_HMAC_SHA2_512_256 :   32        
        }        
        self.configuration_payload_len_bytes = {
        
            INTERNAL_IP4_ADDRESS	                : 4,
            INTERNAL_IP4_NETMASK	                : 4,
            INTERNAL_IP4_DNS	                    : 4,
            INTERNAL_IP4_NBNS	                    : 4,
            INTERNAL_IP4_DHCP		                : 4,
            APPLICATION_VERSION		                : None,
            INTERNAL_IP6_ADDRESS	                : 16,
            INTERNAL_IP6_DNS	                    : 16,
            INTERNAL_IP6_DHCP	                    : 16,
            INTERNAL_IP4_SUBNET	                    : 8,
            SUPPORTED_ATTRIBUTES	                : None,
            INTERNAL_IP6_SUBNET	                    : 17,
            MIP6_HOME_PREFIX	                    : 21,
            INTERNAL_IP6_LINK	                    : None,
            INTERNAL_IP6_PREFIX	                    : 17,
            HOME_AGENT_ADDRESS	                    : None, #16 or 20
            P_CSCF_IP4_ADDRESS	                    : 4,
            P_CSCF_IP6_ADDRESS	                    : 16,
            FTT_KAT		                            : 2,
            EXTERNAL_SOURCE_IP4_NAT_INFO            : 6,
            TIMEOUT_PERIOD_FOR_LIVENESS_CHECK	    : 4,
            INTERNAL_DNS_DOMAIN	                    : None,
            INTERNAL_DNSSEC_TA                      : None      
        }
        self.errors = {
            OK :                            'OK',
            TIMEOUT :                       'TIMEOUT',
            REPEAT_STATE :                  'REPEAT_STATE',
            DECODING_ERROR :                'DECODING_ERROR',
            MANDATORY_INFORMATION_MISSING : 'MANDATORY_INFORMATION_MISSING',
            OTHER_ERROR :                   'OTHER_ERROR'    
        }


    def return_integrity_algorithm_name(self):        
        integ_alg = {
            AUTH_HMAC_MD5_96 : "HMAC_MD5_96 [RFC2403]",
            AUTH_HMAC_SHA1_96 : "HMAC_SHA1_96 [RFC2404]",
            AUTH_HMAC_SHA2_256_128 : "HMAC_SHA2_256_128 [RFC4868]", 
            AUTH_HMAC_SHA2_384_192 : "HMAC_SHA2_384_192 [RFC4868]",
            AUTH_HMAC_SHA2_512_256 : "HMAC_SHA2_512_256 [RFC4868]",
            NONE : "NONE [RFC4306]"
        }
        return integ_alg.get(self.negotiated_integrity_algorithm,'UNKNOWN')
    
    def return_encryption_algorithm_name(self):
        encr_alg = ''
        key_size = self.negotiated_encryption_algorithm_key_size
        if key_size == 128 and self.negotiated_encryption_algorithm == ENCR_AES_CBC:
            encr_alg = "AES-CBC-128 [RFC3602]"
        elif key_size == 256 and self.negotiated_encryption_algorithm == ENCR_AES_CBC:
            encr_alg = "AES-CBC-256 [RFC3602]"
        elif self.negotiated_encryption_algorithm == ENCR_NULL:
            encr_alg = "NULL [RFC2410]"
        return encr_alg
    
    def return_integrity_algorithm_child_name(self):
        integ_alg = {
            AUTH_HMAC_MD5_96 : "HMAC-MD5-96 [RFC2403]",
            AUTH_HMAC_SHA1_96 : "HMAC-SHA-1-96 [RFC2404]",
            AUTH_HMAC_SHA2_256_128 : "HMAC-SHA-256-128 [RFC4868]", 
            AUTH_HMAC_SHA2_384_192 : "HMAC-SHA-384-192 [RFC4868]",
            AUTH_HMAC_SHA2_512_256 : "HMAC-SHA-512-256 [RFC4868]",
            NONE : "NULL"
        }
        return integ_alg.get(self.negotiated_integrity_algorithm_child,'UNKNOWN')        
    
    def return_encryption_algorithm_child_name(self):
        encr_alg = ''
        if self.negotiated_encryption_algorithm_child == ENCR_AES_CBC:
            encr_alg = "AES-CBC [RFC3602]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_8:
            encr_alg = "AES-GCM [RFC4106]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_12:
            encr_alg = "AES-GCM [RFC4106]"
        elif self.negotiated_encryption_algorithm_child == ENCR_AES_GCM_16:
            encr_alg = "AES-GCM [RFC4106]"            
        elif self.negotiated_encryption_algorithm_child == ENCR_NULL:
            encr_alg = "NULL"
        return encr_alg    
    
    def print_ikev2_decryption_table(self):
        print('IKEv2 DECRYPTION TABLE INFO (Wireshark):')
        text = toHex(self.ike_spi_initiator) + ',' + toHex(self.ike_spi_responder) + ','
        text += toHex(self.SK_EI) + ',' + toHex(self.SK_ER) + ',"' + self.return_encryption_algorithm_name() + '",'
        text += toHex(self.SK_AI) + ',' + toHex(self.SK_AR) + ',"' + self.return_integrity_algorithm_name() + '"'
        print(text)
        text = toHex(self.ike_spi_responder) + ',' + toHex(self.ike_spi_initiator) + ','
        text += toHex(self.SK_ER) + ',' + toHex(self.SK_EI) + ',"' + self.return_encryption_algorithm_name() + '",'
        text += toHex(self.SK_AR) + ',' + toHex(self.SK_AI) + ',"' + self.return_integrity_algorithm_name() + '"'
        print(text)


    def print_esp_sa(self):
        print('ESP SA INFO (wireshark):')
        text = '"IPv4","' + self.source_address + '","' + self.epdg_address + '","0x' + toHex(self.spi_resp_child)
        text += '","' + self.return_encryption_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_EI)
        text += '","' + self.return_integrity_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_AI) + '"'
        print(text)
        text = '"IPv4","' + self.epdg_address + '","' + self.source_address + '","0x' + toHex(self.spi_init_child)
        text += '","' + self.return_encryption_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_ER)
        text += '","' + self.return_integrity_algorithm_child_name() + '","0x' + toHex(self.SK_IPSEC_AR) + '"'
        print(text)


       
    def set_timeout(self,value):
        self.timeout = value
        
    def set_udp(self):
        self.socket_type = UDP

    def create_socket(self,client_address):
        
        if self.socket_type == UDP:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            exit()
            
        self.socket.bind(client_address)                
        self.socket.settimeout(self.timeout)


    def create_socket_nat(self,client_address):
        
        if self.socket_type == UDP:
            self.socket_nat = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            exit()
            
        self.socket_nat.bind(client_address)                
        self.socket_nat.settimeout(self.timeout)

    def create_socket_esp(self,client_address):
        self.socket_esp = socket.socket(socket.AF_INET, socket.SOCK_RAW, ESP_PROTOCOL)
        self.socket_esp.bind(client_address)    
        
    def set_server(self,address):
        self.server_address = (address,self.port)

    def set_server_nat(self,address):
        self.server_address_nat = (address,self.port_nat)

    def set_server_esp(self,address):
        self.server_address_esp = (address,0)

    def send_data(self, data):
        if self.userplane_mode == ESP_PROTOCOL:
            self.socket.sendto(data, self.server_address)
        else:
            self.socket_nat.sendto(b'\x00'*4 + data, self.server_address_nat)

    def return_random_bytes(self,size):
        if size == 0: return b''
        if size == 4: return struct.pack('!I', random.randrange(pow(2,32)-1))
        if size == 8: return struct.pack('!Q', random.randrange(pow(2,64)-1))
        if size == 16: return struct.pack('!Q', random.randrange(pow(2,64)-1)) + struct.pack('!Q', random.randrange(pow(2,64)-1))

    def return_random_int(self,size):
        if size == 4: return random.randrange(pow(2,32)-1)
        if size == 8: return random.randrange(pow(2,64)-1)
        if size == 16: return random.randrange(pow(2,128)-1)



    def return_flags(self,value): #works with value or tuple
        
        if type(value) is int:
            rvi = (value//8)%8
            return (rvi // 4, (rvi//2)%2, rvi%2)
        else: #is a tuple with (r,v,i)
            return 32*value[0]+16*value[1]+8*value[2]
            
            
            
    def dh_create_private_key_and_public_bytes(self,key_size):
        prime = {
             768: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF,
            1024: 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF,                 
            1536: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff,
            2048: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aacaa68ffffffffffffffff,
            3072: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a93ad2caffffffffffffffff,
            4096: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c934063199ffffffffffffffff,
            6144: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dcc4024ffffffffffffffff,
            8192: 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca18217c32905e462e36ce3be39e772c180e86039b2783a2ec07a28fb5c55df06f4c52c9de2bcbf6955817183995497cea956ae515d2261898fa051015728e5a8aaac42dad33170d04507a33a85521abdf1cba64ecfb850458dbef0a8aea71575d060c7db3970f85a6e1e4c7abf5ae8cdb0933d71e8c94e04a25619dcee3d2261ad2ee6bf12ffa06d98a0864d87602733ec86a64521f2b18177b200cbbe117577a615d6c770988c0bad946e208e24fa074e5ab3143db5bfce0fd108e4b82d120a92108011a723c12a787e6d788719a10bdba5b2699c327186af4e23c1a946834b6150bda2583e9ca2ad44ce8dbbbc2db04de8ef92e8efc141fbecaa6287c59474e6bc05d99b2964fa090c3a2233ba186515be7ed1f612970cee2d7afb81bdd762170481cd0069127d5b05aa993b4ea988d8fddc186ffb7dc90a6c08f4df435c93402849236c3fab4d27c7026c1d4dcb2602646dec9751e763dba37bdf8ff9406ad9e530ee5db382f413001aeb06a53ed9027d831179727b0865a8918da3edbebcf9b14ed44ce6cbaced4bb1bdb7f1447e6cc254b332051512bd7af426fb8f401378cd2bf5983ca01c64b92ecf032ea15d1721d03f482d7ce6e74fef6d55e702f46980c82b5a84031900b1c9e59e7c97fbec7e8f323a97a7e36cc88be0f1d45b7ff585ac54bd407b22b4154aacc8f6d7ebf48e1d814cc5ed20f8037e0a79715eef29be32806a1d58bb7c5da76f550aa3d8a1fbff0eb19ccb1a313d55cda56c9ec2ef29632387fe8d76e3c0468043e8f663f4860ee12bf2d5b0b7474d6e694f91e6dbe115974a3926f12fee5e438777cb6a932df8cd8bec4d073b931ba3bc832b68d9dd300741fa7bf8afc47ed2576f6936ba424663aab639c5ae4f5683423b4742bf1c978238f16cbe39d652de3fdb8befc848ad922222e04a4037c0713eb57a81a23f0c73473fc646cea306b4bcbc8862f8385ddfa9d4b7fa2c087e879683303ed5bdd3a062b3cf5b3a278a66d2a13f83f44f82ddf310ee074ab6a364597e899a0255dc164f31cc50846851df9ab48195ded7ea1b1d510bd7ee74d73faf36bc31ecfa268359046f4eb879f924009438b481c6cd7889a002ed5ee382bc9190da6fc026e479558e4475677e9aa9e3050e2765694dfc81f56e880b96e7160c980dd98edd3dfffffffffffffffff            
        }    
        g = 2        
        self.pn = dh.DHParameterNumbers(prime.get(key_size),g)
        parameters = self.pn.parameters()
        self.dh_private_key = parameters.generate_private_key()
        self.dh_public_key_bytes = self.dh_private_key.public_key().public_numbers().y.to_bytes(key_size//8,'big')
        
        
    def dh_calculate_shared_key(self,peer_public_key_bytes):
        peer_public_numbers = dh.DHPublicNumbers(int.from_bytes(peer_public_key_bytes, byteorder='big'), self.pn)
        peer_public_key = peer_public_numbers.public_key()
        self.dh_shared_key = self.dh_private_key.exchange(peer_public_key)
        
        print('DIFFIE-HELLMAN KEY',toHex(self.dh_shared_key))
        
        
    def get_identity(self):
            imsi = return_imsi(self.com_port)
            self.imsi = imsi
            self.set_identification(IDI,ID_RFC822_ADDR,'0' + self.imsi + '@nai.epc.mnc' + self.mnc + '.mcc' + self.mcc + '.3gppnetwork.org')
    
    def encode_eap_at_identity(self, identity):
        """ Returns the EAP AT Identity as bytes """
        # 4 bytes -> header (type, at_len, identity_len)
        full_len = 4 + len(identity)
        at_len = int(full_len / 4)
        pad = 0
        if full_len % 4:
            pad = 4 - (full_len % 4)
            at_len += 1
        # 0e -> AT_IDENTITY
        eap_at_identity = (bytes([0x0e, at_len])
                + struct.pack('>H', len(identity))
                + identity.encode("utf-8")
                + pad * b'\x00')
        return eap_at_identity
        
    def eap_keys_calculation(self,ck, ik):
        identity = self.identification_initiator[1].encode('utf-8') #idi value
        digest = hashes.Hash(hashes.SHA1())
        digest.update(identity + ik + ck)
        MK = digest.finalize()
        print('MK',toHex(MK))
        
        result = b''
        xval = MK
        modulus = pow(2,160)
        
        for i in range(4):
            w0 = sha1_dss(xval)
            xval = ((int.from_bytes(xval,'big') + int.from_bytes(w0, 'big') + 1 ) % modulus).to_bytes(20,'big')
            w1 = sha1_dss(xval)
            xval = ((int.from_bytes(xval,'big') + int.from_bytes(w1, 'big') + 1 ) % modulus).to_bytes(20,'big')
            
            result += w0 + w1

        # return     
        return result[0:16],result[16:32],result[32:96],result[96:160],MK
        
        
    def eap_keys_calculation_fast_reauth(self,counter, nonce_s):
        identity = self.identification_initiator[1].encode('utf-8') #idi value
        digest = hashes.Hash(hashes.SHA1())
        digest.update(identity + struct.pack('!H',counter) + nonce_s + self.MK)
        XKEY = digest.finalize()
        print('XKEY',toHex(XKEY))
        
        result = b''
        xval = XKEY
        modulus = pow(2,160)
        
        for i in range(4):
            w0 = sha1_dss(xval)
            xval = ((int.from_bytes(xval,'big') + int.from_bytes(w0, 'big') + 1 ) % modulus).to_bytes(20,'big')
            w1 = sha1_dss(xval)
            xval = ((int.from_bytes(xval,'big') + int.from_bytes(w1, 'big') + 1 ) % modulus).to_bytes(20,'big')
            
            result += w0 + w1

        # return     
        return result[0:64],result[64:128],XKEY        
        
    def build_eap_aka_response(self, eap_identifier, res):
        """
        Build EAP-AKA Response payload with proper length calculation and padding.
        
        Args:
            eap_identifier: EAP packet identifier
            res: RES value (4-16 bytes according to 3GPP standard)
            
        Returns:
            Complete EAP-AKA response payload with proper length and padding
        """
        # Validate RES length (must be 4-16 bytes according to 3GPP TS 33.102)
        res_len = len(res)
        if res_len < 4 or res_len > 16:
            raise ValueError(f"RES length must be between 4-16 bytes, got {res_len}")
        
        # EAP-AKA fixed parts
        eap_code = bytes([2])  # Response
        eap_id = bytes([eap_identifier])
        eap_aka_header = fromHex('1701000003030040')  # EAP-AKA Challenge Response header
        eap_aka_header = fromHex('1701000003')  # EAP-AKA Challenge Response header
        eap_res_bit_len = struct.pack('!H', res_len * 8)
        at_mac_header = fromHex('0b050000')  # AT_MAC attribute header (16 bytes follow)
        
        # Calculate payload length before MAC
        # Structure: Code(1) + ID(1) + Length(2) + EAP-AKA Header(8) + RES(var) + AT_MAC(20)
        base_length = 1 + 1 + 2 + len(eap_aka_header) + 3 + res_len + len(at_mac_header) + 16
        
        # EAP-AKA payloads must be multiples of 4 bytes - add padding if needed
        padding_needed = (4 - (base_length % 4)) % 4
        eap_res_4bytes_len = struct.pack('!B', (res_len + padding_needed) // 4 + 1)
        padding = bytes(padding_needed)
        
        # Final length including padding
        total_length = base_length + padding_needed
        
        # Build length field (2 bytes, big endian)
        length_bytes = struct.pack('!H', total_length)
        
        # Construct payload without MAC (MAC placeholder is 16 zero bytes)
        eap_payload_response = (eap_code + 
                              eap_id + 
                              length_bytes + 
                              eap_aka_header + 
                              eap_res_4bytes_len + 
                              eap_res_bit_len + 
                              res + 
                              padding +  # Add padding after RES if needed
                              at_mac_header + 
                              bytes(16))  # MAC placeholder
        
        return eap_payload_response
        
#######################################################################################################################
#######################################################################################################################
################                            D E C O D E     F U N C T I O N S                          ################
#######################################################################################################################
#######################################################################################################################

        
    def decode_header(self, data):
        try:
        #if True:        
            self.ike_decoded_header['initiator_spi'] = data[0:8]
            self.ike_decoded_header['responder_spi'] = data[8:16]
            self.ike_decoded_header['next_payload'] = data[16]
            self.ike_decoded_header['major_version'] = data[17] // 16
            self.ike_decoded_header['minor_version'] = data[17] % 16        
            self.ike_decoded_header['exchange_type'] = data[18]
            self.ike_decoded_header['flags'] = self.return_flags(data[19])        
            self.ike_decoded_header['message_id'] = struct.unpack("!I",data[20:24])[0]
            self.ike_decoded_header['length'] =  struct.unpack("!I", data[24:28])[0]  #header + payloads
            
            
            if self.ike_spi_responder == (0).to_bytes(8,'big') and self.ike_spi_initiator == self.ike_decoded_header['initiator_spi'] :
                self.ike_spi_responder = self.ike_decoded_header['responder_spi']
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = False
                return
                
            if self.ike_spi_initiator == self.ike_decoded_header['initiator_spi'] and self.ike_spi_responder == self.ike_decoded_header['responder_spi']:
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = False
                return

            if self.ike_spi_initiator_old == self.ike_decoded_header['initiator_spi'] and self.ike_spi_responder_old == self.ike_decoded_header['responder_spi']:
                self.ike_decoded_header_ok = True
                self.old_ike_message_received = True
                return
                
            self.ike_decoded_header_ok = False
            return
        except:
            self.ike_decoded_header_ok = False


    def decode_generic_payload_header(self,data, position, payload_type):
        ike_decoded_payload_header = {}
        ike_decoded_payload_header['next_payload'] = data[position]
        ike_decoded_payload_header['C'] = data[position+1] // 128
        ike_decoded_payload_header['length'] =  struct.unpack("!H", data[position+2:position+4])[0]
        ike_decoded_payload_header['data'] = data[position+4:position+ike_decoded_payload_header['length']]      
        
        #to be used for SK decryption
        self.current_next_payload = ike_decoded_payload_header['next_payload']
        
        if payload_type in self.decodable_payloads:
            ike_decoded_payload_header['decoded'] = [payload_type, self.decode_payload_type(payload_type, ike_decoded_payload_header['data'])]
        else:
            ike_decoded_payload_header['decoded'] = [payload_type, None]
        
        position += ike_decoded_payload_header['length']
        return position, ike_decoded_payload_header['decoded'], ike_decoded_payload_header['next_payload'] 

    
    def decode_payload(self, data, next_payload, position=28): #by default it uses position 28 for normal
        
        decoded_payload = []
        while position < len(data):
            
            position, payload_decoded, next_payload = self.decode_generic_payload_header(data, position, next_payload)
            decoded_payload.append(payload_decoded)
        
        return (True, decoded_payload)
         
    def decode_ike(self, data):
        self.current_packet_received = data
        
        try:        
        #if True:
            self.decode_header(data)
            if self.ike_decoded_header_ok == False:
                self.ike_decoded_ok = False
            else:
                
                (self.decoded_payload_ok, self.decoded_payload) = self.decode_payload(data, self.ike_decoded_header['next_payload'])
                if self.decoded_payload_ok == False:
                    self.ike_decoded_ok = False
                else:
                    self.ike_decoded_ok = True
                    print('received decoded message:')
                    print(self.decoded_payload)
        except:
            self.ike_decoded_ok = False


    def decode_payload_type(self, type, data):
        payload_type = {
            SA:      self.decode_payload_type_sa  ,
            KE:      self.decode_payload_type_ke  ,
            IDI:     self.decode_payload_type_idi  ,
            IDR:     self.decode_payload_type_idr  ,
            CERT:    self.decode_payload_type_cert  ,
            CERTREQ: self.decode_payload_type_certreq  ,
            AUTH:    self.decode_payload_type_auth  ,
            NINR:    self.decode_payload_type_ninr  ,
            N:       self.decode_payload_type_n  ,
            D:       self.decode_payload_type_d  ,
            V:       self.decode_payload_type_v  ,
            TSI:     self.decode_payload_type_tsi_tsr  ,
            TSR:     self.decode_payload_type_tsi_tsr  ,
            SK:      self.decode_payload_type_sk  ,
            CP:      self.decode_payload_type_cp  ,
            EAP:     self.decode_payload_type_eap  
        }
        func = payload_type.get(type, self.unsupported_payload_type)     
        return func(data)


    def decode_payload_type_sa(self, data):
        spi = b''
        if data[5]!= 0:
            spi = data[8:8+data[6]]            
        return [data[4],data[5],spi] # proposal number, protocol_id, spi
        
    def decode_payload_type_ke(self, data):
        return [struct.unpack("!H", data[0:2])[0], data[4:]] # diffie-hellman group, key
        
        
    def decode_payload_type_idi(self, data):
        return [data[0],data[4:]]
        
    def decode_payload_type_idr(self, data):
        return [data[0],data[4:]]
        
    def decode_payload_type_cert(self, data):
        return [data[0],data[1:]]
        
    def decode_payload_type_certreq(self, data):
        return [data[0],data[1:]]
        
    def decode_payload_type_auth(self, data):
        return [data[0],data[4:]]
    
    def decode_payload_type_ninr(self, data):
        return [data]  # nounce_received
        
    def decode_payload_type_n(self, data):
        spi = b''
        notification_data = b''
        if data[1]!= 0: #spi present
            spi = data[4:4+data[1]]
        if len(data)>4 +data[1]: #notification data present
            notification_data = data[4+data[1]:]
        # Debug: log every received IKEv2 Notify (type name + code, protocol, and data hex).
        # Helps diagnose ePDG behaviour (errors, BACKOFF_TIMER, DEVICE_IDENTITY, P-CSCF-reselect,
        # …) and is groundwork for fuller 3GPP TS 24.302 handling. Goes to the IKE (charon) log.
        try:
            ntype = struct.unpack("!H", data[2:4])[0]
            proto = data[0]
            klass = "ERROR" if ntype < 16384 else "STATUS"
            extra = ""
            if notification_data:
                hexd = notification_data.hex()
                extra = " data=" + (hexd if len(hexd) <= 64 else hexd[:64] + "...")
            if spi:
                extra += " spi=" + spi.hex()
            desc = notify_describe(ntype)
            if desc:
                extra += "  # " + desc
            swu_log("received Notify: %s (%d, %s) protocol=%d%s" %
                    (notify_name(ntype), ntype, klass, proto, extra))
        except Exception:
            pass
        return [data[0],struct.unpack("!H", data[2:4])[0],spi,notification_data] # protocol_id, notify_message_type, spi, notification_data
        
    def decode_payload_type_d(self, data):
        spi = b''
        spi_list = []
        num_of_spi = 0
        if data[1]!= 0: #spi present
            num_of_spi = struct.unpack("!H", data[2:4])[0]            
            for i in range(num_of_spi):
                spi_list.append(data[4+i*data[1]:4+(i+1)*data[1]])
            
        return [data[0],num_of_spi, spi_list] # [protocol_id, number of spi, [spi1, spi2, ... spi n]]
            
    def decode_payload_type_v(self, data):
        return [data]
        
    def decode_payload_type_tsi_tsr(self, data):
        num_of_ts = data[0]
        ts_list = []
        position = 4
        for i in range(num_of_ts):
            ts_type = data[position]
            protocol_id = data[position+1]
            start_port, end_port = struct.unpack("!H", data[position+4:position+6])[0], struct.unpack("!H", data[position+6:position+8])[0]
            if ts_type == TS_IPV4_ADDR_RANGE:
                starting_address = socket.inet_ntop(socket.AF_INET,data[position+8:position+12])
                ending_address = socket.inet_ntop(socket.AF_INET,data[position+12:position+16])
                position += 16                  
            elif ts_type == TS_IPV6_ADDR_RANGE:
                starting_address = socket.inet_ntop(socket.AF_INET6,data[position+8:position+24])
                ending_address = socket.inet_ntop(socket.AF_INET6,data[position+24:position+40])                
                position += 40
        
            ts_list.append((ts_type,protocol_id,start_port,end_port,starting_address,ending_address))     
        return [num_of_ts,ts_list]
       
       
       
       
    ######### CIPHERED PAYLOAD ######  
    ######### CIPHERED PAYLOAD ######  
    ######### CIPHERED PAYLOAD ######      
    def decode_payload_type_sk(self, data):
        if self.negotiated_encryption_algorithm in (ENCR_AES_CBC,):
            vector = data[0:16]
            hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)
            hash_data = data[-hash_size:]
        
            encrypted_data = data[16:len(data)-hash_size]
            
            if self.ike_decoded_header['flags'][2] == ROLE_RESPONDER:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_ER_old), modes.CBC(vector))                  
                else:
                    cipher = Cipher(algorithms.AES(self.SK_ER), modes.CBC(vector))  
            else:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_EI_old), modes.CBC(vector)) 
                else:                
                    cipher = Cipher(algorithms.AES(self.SK_EI), modes.CBC(vector))  
                
            decryptor = cipher.decryptor()
            
            uncipher_data = decryptor.update(encrypted_data) + decryptor.finalize()
                       
            padding_length = uncipher_data[-1]
            ike_payload = uncipher_data[0:-padding_length-1]
            
            (result_ok, decoded_payload) = self.decode_payload(ike_payload, self.current_next_payload,0)
            if result_ok == True:
                return decoded_payload


        elif self.negotiated_encryption_algorithm in (ENCR_NULL,):
            hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)
            hash_data = data[-hash_size:]
        
            ike_payload = data[0:len(data)-hash_size-self.sk_ENCR_NULL_pad_length]                
            (result_ok, decoded_payload) = self.decode_payload(ike_payload, self.current_next_payload,0)
            if result_ok == True:
                return decoded_payload                
                
                
        
    def decode_payload_type_cp(self, data):
        cfg_type = data[0]
        attribute_list = []
        position=4
        while position < len(data):        
            attribute_type = struct.unpack("!H", data[position:position+2])[0]
            length = struct.unpack("!H", data[position+2:position+4])[0]
            attribute_value = b''
            if length > 0: 
                att_len = self.configuration_payload_len_bytes.get(attribute_type)
                if att_len == 4: #ip
                    attribute_value = socket.inet_ntop(socket.AF_INET,data[position+4:position+8])
                    attribute_list.append((attribute_type,attribute_value))
                elif att_len == 8: #ip /netmask
                    attribute_value_1 = socket.inet_ntop(socket.AF_INET,data[position+4:position+8])
                    attribute_value_2 = socket.inet_ntop(socket.AF_INET,data[position+8:position+12])
                    attribute_list.append((attribute_type,attribute_value_1,attribute_value_2))
                elif att_len == 16: #ipv6
                    attribute_value = socket.inet_ntop(socket.AF_INET6,data[position+4:position+20])
                    attribute_list.append((attribute_type,attribute_value))    
                elif att_len == 17: #ipv6 + prefix
                    attribute_value_1 = socket.inet_ntop(socket.AF_INET6,data[position+4:position+20])
                    attribute_value_2 = data[position+21]
                    attribute_list.append((attribute_type,attribute_value_1, attribute_value_2))                      
                else:
                    attribute_value = data[position+4:position+4+length]
                    attribute_list.append((attribute_type,attribute_value))
            else:
                attribute_list.append((attribute_type,attribute_value))
            position += length + 4
        return [cfg_type,attribute_list]
        
    def decode_payload_type_eap(self, data):
        code = data[0] #1- request, 2-response, 3-success, 4-failure
        identifier = data[1]
        if code in (EAP_SUCCESS,EAP_FAILURE): 
            return [code,identifier]
        elif code in (EAP_REQUEST,EAP_RESPONSE):
            if data[4] == EAP_AKA:
                return [code,identifier,data[4],data[5],self.decode_eap_attributes(data[8:])] #code, identifier, type, sub type, [attributes list]
            else:
                return [code,identifier,data[4],data[5:]]
        else:
            return []

    def unsupported_payload_type(self, data):
        return None
        

    def decode_eap_attributes(self, data):
        eap_aka_decoded = []
        position = 0
        while position < len(data):
            attribute = data[position]
            if attribute in (AT_PERMANENT_ID_REQ,AT_ANY_ID_REQ,AT_FULLAUTH_ID_REQ,AT_RESULT_IND,AT_COUNTER,AT_COUNTER_TOO_SMALL,AT_CLIENT_ERROR_CODE,AT_NOTIFICATION):
                eap_aka_decoded.append((attribute,struct.unpack("!H", data[position+2:position+4])[0]))
            elif attribute in (AT_IDENTITY,AT_RES,AT_NEXT_PSEUDONYM,AT_NEXT_REAUTH_ID):
                eap_aka_decoded.append((attribute,data[position+4:position+4+struct.unpack("!H", data[position+2:position+4])[0]]))
            elif attribute in (AT_RAND,AT_AUTN,AT_IV,AT_MAC,AT_NONCE_S):                
                eap_aka_decoded.append((attribute,data[position+4:position+20]))
            elif attribute in (AT_AUTS,):                
                eap_aka_decoded.append((attribute,data[position+2:position+16]))
            elif attribute in (AT_CHECKCODE,):               
                if data[position+1] == 0:            
                    eap_aka_decoded.append((attribute,struct.unpack("!H", data[position+2:position+4])[0]))
                else:
                    eap_aka_decoded.append((attribute,data[position+4:position+24]))
            
            elif attribute in (AT_ENCR_DATA,):
                eap_aka_decoded.append((attribute,data[position+4:position+4*data[position+1]]))

            elif attribute in (AT_PADDING,):
                eap_aka_decoded.append((attribute,data[position+2:position+4*data[position+1]]))
            
            position += data[position+1]*4
        return eap_aka_decoded
        
#######################################################################################################################
#######################################################################################################################
################                           E N C O D E     F U N C T I O N S                           ################
#######################################################################################################################
#######################################################################################################################
        
    def set_sa_list(self,sa_list):
        self.sa_list = sa_list    

    def set_sa_list_child(self,sa_list):
        self.sa_list_child = sa_list   

    def set_ts_list(self,type, ts_list):
        if type == TSI: self.ts_list_initiator = ts_list
        if type == TSR: self.ts_list_responder = ts_list    

    def set_cp_list(self, cp_list):
         self.cp_list = cp_list

    def set_device_identity(self, imei, imeisv=""):
        """Set the IMEI / IMEISV used to answer the ePDG's DEVICE_IDENTITY request.

        IMEI: digits only (a formatted '35212721-360029-6' is accepted and stripped).
        IMEISV: 16 digits; if blank, derive it from the IMEI's first 14 digits (TAC+SNR, i.e.
        without the check digit) + a '00' SVN. Empty IMEI keeps the module defaults so a bare
        run still works."""
        imei_d = "".join(ch for ch in str(imei or "") if ch.isdigit())
        isv_d = "".join(ch for ch in str(imeisv or "") if ch.isdigit())
        if imei_d:
            self.imei = imei_d
        if isv_d:
            self.imeisv = (isv_d + "0" * 16)[:16]
        elif imei_d:
            self.imeisv = (imei_d[:14].ljust(14, "0")) + "00"
        swu_log("device identity set: IMEI=%s IMEISV=%s" % (self.imei, self.imeisv))

    def set_identification(self,payload_type, id_type,value):
        if payload_type == IDI: self.identification_initiator = (id_type, value)
        if payload_type == IDR: self.identification_responder = (id_type, value)        
        
    def set_ike_packet_length(self,packet):
        packet = bytearray(packet)
        packet[24:28] = struct.pack("!I",len(packet))
        return packet

    def encode_header(self,initiator_spi, responder_spi, next_payload, major_version, minor_version, exchange_type, flags, message_id, length = 0):
        header = b''
        header += initiator_spi
        header += responder_spi
        header += bytes([next_payload])
        header += bytes([major_version*16+minor_version])
        header += bytes([exchange_type])
        header += bytes([self.return_flags(flags)])
        header += struct.pack("!I",message_id)  
        header += struct.pack("!I",length)  
        return header
        

    def encode_generic_payload_header(self,next_payload,c,data):
        payload = b''
        payload += bytes([next_payload])
        payload += bytes([c*128])
        payload += struct.pack("!H",len(data)+4)  
        payload += data
        return payload
        
        
    def encode_payload_type_sa(self, sa_list):
        payload_sa = b''
        proposal_list = []
        self.sa_spi_list = []
        m = 0
        
        proposal = 1
        for i in sa_list:
            transform_list = []
            
            protocol_id = i[0][0]
            spi_size = i[0][1]
            spi_bytes = self.return_random_bytes(spi_size)
            self.sa_spi_list.append(spi_bytes)

            for m in range(1,len(i)): #transform_list
                
                transform_type = i[m][0]
                transform_id = i[m][1]
                if len(i[m])==3: #attributes 
                    attribute_type = i[m][2][0][0]
                    attribute_format = i[m][2][0][1]
                    attribute_value = i[m][2][1]
                    if attribute_format == 0: #TLV: Value in bytes format
                        attribute_bytes = struct.pack("!H",attribute_type) 
                        attribute_bytes += struct.pack("!H",len(attribute_value)) 
                        attribute_bytes += attribute_value
                    else: # TV
                        attribute_bytes = struct.pack("!H",32768+attribute_type) 
                        attribute_bytes += struct.pack("!H",attribute_value)
                else:
                    attribute_bytes = b''                
                
                
                if proposal == 1 and transform_type == D_H and protocol_id == IKE:
                    self.dh_create_private_key_and_public_bytes(self.iana_diffie_hellman.get(transform_id))   
                    self.dh_group_num = transform_id       
     
                
                last = 3
                if m == len(i)-1: last = 0 # last transform
                    
                transform_bytes = bytes([last]) + b'\x00\x00\x00' + bytes([transform_type]) + b'\x00' + struct.pack("!H",transform_id) + attribute_bytes
                transform_bytes = bytearray(transform_bytes)
                transform_bytes[2:4] = struct.pack("!H",len(transform_bytes))

                transform_list.append(transform_bytes)
                           
            last = 2
            if proposal == len(sa_list): last = 0 #last proposal
            
            proposal_bytes = bytes([last]) + b'\x00\x00\x00' + bytes([proposal]) + bytes([protocol_id]) + bytes([spi_size]) + bytes([m]) + spi_bytes + b''.join(transform_list)            
                
            proposal_bytes = bytearray(proposal_bytes)
            proposal_bytes[2:4] = struct.pack("!H",len(proposal_bytes))
            
            proposal_list.append(proposal_bytes)


            proposal += 1

        return b''.join(proposal_list)




    def encode_payload_type_ke(self):        
        payload_ke = struct.pack("!H",self.dh_group_num) + b'\x00\x00' + self.dh_public_key_bytes
        return payload_ke


    def encode_payload_type_ninr(self, lowest = 0):
        if lowest == 0:    
            payload_ninr = self.return_random_bytes(16)
        elif lowest == -1:
            payload_ninr = b'\x00'*8 + self.return_random_bytes(8)
        elif lowest == 1:
            payload_ninr = b'\xff'*8 + self.return_random_bytes(8)
        self.nounce = payload_ninr
        return payload_ninr


    def encode_payload_type_tsi(self):
        return self.encode_payload_type_ts(TSI)

    def encode_payload_type_tsr(self):
        return self.encode_payload_type_ts(TSR)
        
    def encode_payload_type_ts(self,type):
        if type == TSI: ts_list = self.ts_list_initiator
        if type == TSR: ts_list = self.ts_list_responder
        
        payload_ts = bytes([len(ts_list)]) + b'\x00\x00\x00'
        
        for i in ts_list:
            ts_type = bytes([i[0]])
            ip_protocol = bytes([i[1]])
            start_port = struct.pack("!H",i[2])
            end_port = struct.pack("!H",i[3])
            if i[0] == TS_IPV4_ADDR_RANGE:
                length = struct.pack("!H",16)
                starting_address = socket.inet_pton(socket.AF_INET,i[4])
                ending_address = socket.inet_pton(socket.AF_INET,i[5])
            elif i[0] == TS_IPV6_ADDR_RANGE:
                length = struct.pack("!H",40)
                starting_address = socket.inet_pton(socket.AF_INET6,i[4])
                ending_address = socket.inet_pton(socket.AF_INET6,i[5])
            payload_ts += ts_type + ip_protocol + length + start_port + end_port + starting_address + ending_address
        
        return payload_ts
        
    def encode_payload_type_cp(self):
    
        payload_cp = bytes([self.cp_list[0]]) + b'\x00\x00\x00'
        for i in self.cp_list[1:]:
            if len(i) == 1: #no value
                payload_cp += struct.pack("!H",i[0]) + b'\x00\x00'
            else:
                length = self.configuration_payload_len_bytes.get(i[0])              
                if length == 4: #ip address
                    value = socket.inet_pton(socket.AF_INET,i[1])
                    payload_cp += struct.pack("!H",i[0]) + struct.pack("!H",4) + value
                elif length == 8: #ip address, netmask
                    value_1, value_2 = socket.inet_pton(socket.AF_INET,i[1]), socket.inet_pton(socket.AF_INET,i[2])
                    payload_cp += struct.pack("!H",i[0]) + struct.pack("!H",8) + value_1 + value_2
                elif length == 16: #ipv6 address
                    value = socket.inet_pton(socket.AF_INET6,i[1])
                    payload_cp += struct.pack("!H",i[0]) + struct.pack("!H",16) + value
                elif length == 17: #ipv6 address, mask length
                    value = socket.inet_pton(socket.AF_INET6,i[1])
                    payload_cp += struct.pack("!H",i[0]) + struct.pack("!H",17) + value + bytes([i[2]])
                else: # not stricted
                    payload_cp += struct.pack("!H",i[0]) + struct.pack("!H",len(i[1])) + i[1]

        return payload_cp
        
    def encode_payload_type_idi(self):
        return self.encode_payload_type_id(IDI)

    def encode_payload_type_idr(self):
        return self.encode_payload_type_id(IDR)
        
    def encode_payload_type_id(self,type): #id
        if type == IDI: (id_type,value) = self.identification_initiator
        if type == IDR: (id_type,value) = self.identification_responder
        if id_type in (ID_FQDN, ID_RFC822_ADDR): 
            value = value.encode('utf-8')
        elif id_type == ID_IPV4_ADDR:
            value = socket.inet_pton(socket.AF_INET,value)
        elif id_type == ID_IPV6_ADDR:
            value = socket.inet_pton(socket.AF_INET6,value)
        #else binary, so use value as is.    
        payload_id = bytes([id_type]) + b'\x00\x00\x00' + value

        return payload_id
 
 
 
    def encode_payload_type_eap(self): 
        return self.eap_payload_response

    def encode_payload_type_auth(self,auth_method): 
        return bytes([auth_method]) + b'\x00'*3 + self.AUTH_payload
 
    def encode_payload_type_d(self, protocol, spi_list = b''): 
        if protocol == IKE:
            return bytes([IKE]) + b'\x00\x00\x00'
        elif protocol == ESP:
            num_spi = len(spi_list) // 4
            return bytes([ESP]) + b'\x04' + struct.pack("!H",num_spi) + spi_list
            
 
    def encode_payload_type_n(self,protocol,spi,notify_message_type,notification_data= b''):
        spi_size = len(spi)
        return bytes([protocol]) + bytes([spi_size]) + struct.pack("!H",notify_message_type) + spi + notification_data


    def encode_device_identity_notification_data(self):
        """ Encodes the DEVICE_IDENTITY notification data.
        Format: [2 bytes length][1 byte identity type][BCD encoded IMEI/IMEISV]
        Identity type 0x01 = IMEI (15 digits, padded with F to 16)
        Identity type 0x02 = IMEISV (16 digits)
        Uses the per-instance self.imei / self.imeisv (set via set_device_identity).
        """
        if self.device_identity_type == 0x02:
            identity_type = 0x02
            digits = (self.imeisv or IMEISV)
        else:  # 0x01 or fallback
            identity_type = 0x01
            imei = (self.imei or IMEI)
            digits = imei[:15] + 'F'  # pad 15-digit IMEI to 16 chars with trailing F
        swu_log("answering DEVICE_IDENTITY (type=0x%02x) with %s" %
                (identity_type, digits.rstrip('F')))

        bcd = b''
        for i in range(0, len(digits), 2):
            low_nibble  = int(digits[i],   16)
            high_nibble = int(digits[i+1], 16)
            bcd += bytes([low_nibble | (high_nibble << 4)])

        data = bytes([identity_type]) + bcd
        return struct.pack("!H", len(data)) + data


    def encode_payload_type_sk(self,ike_packet):

        hash_size = self.integ_key_truncated_len_bytes.get(self.negotiated_integrity_algorithm)
        
        if self.negotiated_encryption_algorithm in (ENCR_AES_CBC,):
            vector = self.return_random_bytes(16)
            data_to_encrypt = ike_packet[28:]
        
            res = 16 - (len(data_to_encrypt) % 16)
            if res>1:
                data_to_encrypt += b'\x00'*(res-1) + bytes([res-1])
            else:
                data_to_encrypt += b'\x00'*(15+res) + bytes([15+res])
            
            
            flags_role = self.return_flags(ike_packet[19])[2]  
            
            if flags_role == ROLE_INITIATOR:    
                if self.old_ike_message_received == True:            
                    cipher = Cipher(algorithms.AES(self.SK_EI_old), modes.CBC(vector))                
                else:
                    cipher = Cipher(algorithms.AES(self.SK_EI), modes.CBC(vector))
            else:
                if self.old_ike_message_received == True:
                    cipher = Cipher(algorithms.AES(self.SK_ER_old), modes.CBC(vector))                
                else:
                    cipher = Cipher(algorithms.AES(self.SK_ER), modes.CBC(vector))
            
            encryptor = cipher.encryptor()          
            cipher_data = encryptor.update(data_to_encrypt) + encryptor.finalize()
                      
            sk_payload = self.encode_generic_payload_header(ike_packet[16],0,vector + cipher_data + b'\x00'*hash_size) #add a dummy hash to calculate correct length    
            new_ike_packet = ike_packet[0:16] + bytes([SK]) + ike_packet[17:28] + sk_payload        
            new_ike_packet = self.set_ike_packet_length(new_ike_packet)
            new_ike_packet_to_integrity = new_ike_packet[0:-hash_size]           
            hash = self.integ_function.get(self.negotiated_integrity_algorithm) 
            
            if flags_role == ROLE_INITIATOR:  
                if self.old_ike_message_received == True:            
                    h = hmac.HMAC(self.SK_AI_old,hash)                
                else:    
                    h = hmac.HMAC(self.SK_AI,hash)
            else:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AR_old,hash) 
                else:
                    h = hmac.HMAC(self.SK_AR,hash)            
                
            h.update(new_ike_packet_to_integrity)
            hash = h.finalize()[0:hash_size]         
            
            return new_ike_packet_to_integrity + hash
    

        elif self.negotiated_encryption_algorithm in (ENCR_NULL,):

            data_to_encrypt = ike_packet[28:]   
     
                      
            sk_payload = self.encode_generic_payload_header(ike_packet[16],0, data_to_encrypt + b'\x00'*(hash_size + self.sk_ENCR_NULL_pad_length))    
            new_ike_packet = ike_packet[0:16] + bytes([SK]) + ike_packet[17:28] + sk_payload        
            new_ike_packet = self.set_ike_packet_length(new_ike_packet)
            new_ike_packet_to_integrity = new_ike_packet[0:-hash_size]           
            hash = self.integ_function.get(self.negotiated_integrity_algorithm) 
            
            flags_role = self.return_flags(ike_packet[19])[2]            
            if flags_role == ROLE_INITIATOR:  
                if self.old_ike_message_received == True:            
                    h = hmac.HMAC(self.SK_AI_old,hash)                
                else:    
                    h = hmac.HMAC(self.SK_AI,hash)
            else:
                if self.old_ike_message_received == True:
                    h = hmac.HMAC(self.SK_AR_old,hash) 
                else:
                    h = hmac.HMAC(self.SK_AR,hash)            
                
            h.update(new_ike_packet_to_integrity)
            hash = h.finalize()[0:hash_size]         
            
            return new_ike_packet_to_integrity + hash        
        
        
        
        
        
        

#######################################################################################################################
#######################################################################################################################
############                    S T A T E    &    M E S S A G E S     F U N C T I O N S                    ############
#######################################################################################################################
#######################################################################################################################

### USER PLANE FUNCTIONS AND INTER PROCESS COMMUNICATION ####

    def exec_in_netns(self, cmd, shell=True):
        if self.netns_name:
            cmd = "ip netns exec %s %s" % (self.netns_name, cmd)
        print("cmd: %s" % cmd)
        subprocess.call(cmd, shell=shell)


    def set_routes(self):
  
        self.tunnel = self.open_tun(1)
        if self.netns_name:
            # create netns adn move the tun device into it
            subprocess.call("ip netns add %s" % self.netns_name, shell=True)
            subprocess.call("ip link set dev %s netns %s" % (self.tun_device, self.netns_name), shell=True)
            # moving to netns brings device down again
            self.exec_in_netns("ip link set dev %s up" % (self.tun_device))

        if self.ip_address_list != []:
            self.exec_in_netns("ip addr add " + self.ip_address_list[0] + "/32 dev " + self.tun_device)
            #set host route, only  required if no netns
            if not self.netns_name:
                if self.default_gateway is None:
                    self.exec_in_netns("route add " + self.server_address[0] + "/32 gw " + self.get_default_gateway_linux()[0])
                else:
                    self.exec_in_netns("route add " + self.server_address[0] + "/32 gw " + self.default_gateway)
                
            self.exec_in_netns("route add -net 0.0.0.0/1 gw " + self.ip_address_list[0])
            self.exec_in_netns("route add -net 128.0.0.0/1 gw " + self.ip_address_list[0])
        
        if self.ipv6_address_list != []:
            ipv6_address_prefix = ':'.join(self.ipv6_address_list[0].split(':')[0:4])
            ipv6_address_identifier = 'fe80::' + ':'.join(self.ipv6_address_list[0].split(':')[4:8])
            self.exec_in_netns("ip -6 addr add " + ipv6_address_identifier + "/64 dev " + self.tun_device)
            # VoWiFi engine addition: the upstream code only puts a derived link-local on the
            # tun (the assigned global is never assigned). That is fine for a plain data APN
            # where the ePDG routes by tunnel, but IMS/P-CSCF validates the SIP source against
            # the assigned inner address, so Asterisk must be able to source from the assigned
            # global (RFC 6724 then picks it for the global P-CSCF). Assign it additively,
            # leaving the confirmed-working link-local in place.
            if SWU_ASSIGN_IPV6_GLOBAL:
                self.exec_in_netns("ip -6 addr add " + self.ipv6_address_list[0] + "/64 dev " + self.tun_device)
            self.exec_in_netns("route -A inet6 add ::/1 dev " + self.tun_device)
            self.exec_in_netns("route -A inet6 add 8000::/1 dev " + self.tun_device)


        if (self.dns_address_list != [] or self.dnsv6_address_list != []) and \
                (self.netns_name or SWU_WRITE_RESOLV):
            # In the engine container we do NOT rewrite /etc/resolv.conf (guarded off by
            # default): P-CSCF is an explicit IP and clobbering resolv.conf breaks the manager
            # callback + ePDG FQDN resolution. Netns mode still writes its own per-ns resolv.
            if self.netns_name:
                self.add_dir() #create directory for namespace if it doesn't exist
                
                with open("/etc/netns/%s/resolv.conf" % self.netns_name, "w") as file_obj:
                    for i in self.dns_address_list:
                        file_obj.write("nameserver %s\n" % i)
                    for i in self.dnsv6_address_list:
                        file_obj.write("nameserver %s\n" % i)
            else:
                subprocess.call("cp /etc/resolv.conf /etc/resolv.backup.conf", shell=True)  
                subprocess.call("echo > /etc/resolv.conf", shell=True) 
                for i in self.dns_address_list:
                    subprocess.call("echo 'nameserver " + i +"' >> /etc/resolv.conf", shell=True)  
                for i in self.dnsv6_address_list:
                    subprocess.call("echo 'nameserver " + i +"' >> /etc/resolv.conf", shell=True)            

    def add_dir(self):
        if not os.path.isdir('/etc/netns'):        
            os.mkdir('/etc/netns')
        if not os.path.isdir('/etc/netns/' + self.netns_name):   
            os.mkdir('/etc/netns/'  + self.netns_name)

     
    def delete_routes(self):
        if self.netns_name:
            subprocess.call("ip netns del %s" % self.netns_name, shell=True)
        else:
            self.exec_in_netns("route del " + self.server_address[0] + "/32", shell=True)  
            os.close(self.tunnel) 
            if self.dns_address_list != []:
                subprocess.call("cp /etc/resolv.backup.conf /etc/resolv.conf", shell=True)        
      

    def get_default_source_address(self):
    
        proc = subprocess.Popen("/sbin/ifconfig | grep -A 1 " + get_default_gateway_linux()[1] + " | grep inet", stdout=subprocess.PIPE, shell=True)
        output = str(proc.stdout.read())
        if 'addr:' in output:
            addr = output.split('addr:')[1].split()[0]
        else:
            addr = output.split('inet ')[1].split()[0]
        return addr
    
    def get_default_gateway_linux(self):
        """Read the default gateway directly from /proc."""
        with open("/proc/net/route") as fh:
            for line in fh:
                fields = line.strip().split()
                if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                    continue
    
                return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))), fields[0]


    def open_tun(self,n):
        TUNSETIFF = 0x400454ca
        IFF_TUN   = 0x0001
        IFF_TAP   = 0x0002
        IFF_NO_PI = 0x1000 # No Packet Information - to avoid 4 extra bytes
    
        TUNMODE = IFF_TUN | IFF_NO_PI
        MODE = 0
        DEBUG = 0

        self.tun_device = SWU_IFACE

        f = os.open("/dev/net/tun", os.O_RDWR)
        ifs = fcntl.ioctl(f, TUNSETIFF, struct.pack("16sH", bytes(self.tun_device, "utf-8"), TUNMODE))
        subprocess.call("ip link set dev %s up" % self.tun_device, shell=True)

        return f


    def esp_padding(self,length):
        padding = b''
        for i in range(length):
            padding += bytes([i+1])
        return padding

    def encapsulate_esp_packet(self,packet,encr_alg,encr_key,integ_alg,integ_key,spi_resp,sqn):

        hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
        if packet[0] // 16 == 4: #ipv4
            packet_type = 4
        elif packet[0] // 16 == 6: #ipv6
            packet_type = 41
        else:
            return None
        
        if encr_alg in (ENCR_AES_CBC,):
            vector = self.return_random_bytes(16)
            data_to_encrypt = packet
            
            res = 16 - (len(data_to_encrypt) % 16)
            if res>1:
                data_to_encrypt += self.esp_padding(res-2) + bytes([res-2]) + bytes([packet_type])
            else:
                data_to_encrypt += self.esp_padding(14+res) + bytes([14+res]) + bytes([packet_type])
                   
            cipher = Cipher(algorithms.AES(encr_key), modes.CBC(vector))
            encryptor = cipher.encryptor()          
            cipher_data = encryptor.update(data_to_encrypt) + encryptor.finalize()
                      
            new_ike_packet = spi_resp + struct.pack("!I",sqn) + vector + cipher_data         
            
            if hash_size != 0:          
                hash = self.integ_function.get(integ_alg) 
                h = hmac.HMAC(integ_key,hash)
                h.update(new_ike_packet)
                hash = h.finalize()[0:hash_size]         
            else:
                hash = b''
                
            return new_ike_packet + hash

        elif encr_alg in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):
            
            if encr_alg == ENCR_AES_GCM_8: mac_length = 8
            if encr_alg == ENCR_AES_GCM_12: mac_length = 12
            if encr_alg == ENCR_AES_GCM_16: mac_length = 16        
        
            aad = spi_resp + struct.pack("!I",sqn) 
            vector = self.return_random_bytes(8)
          
            data_to_encrypt = packet
            
            res = (len(data_to_encrypt)+2) % 4            
            if res== 0:
                data_to_encrypt += bytes([res]) + bytes([packet_type])                
            else:
                data_to_encrypt += self.esp_padding(4-res) + bytes([4-res]) + bytes([packet_type])                  
                        
            cipher = AES.new(encr_key[:-4], AES.MODE_GCM, nonce=encr_key[-4:] + vector, mac_len=mac_length)
            cipher.update(aad)
            
            cipher_data, tag = cipher.encrypt_and_digest(data_to_encrypt)
                                           
            new_ike_packet = spi_resp + struct.pack("!I",sqn) + vector + cipher_data + tag
          
            return new_ike_packet

        elif encr_alg in (ENCR_NULL,):
            
            new_ike_packet = spi_resp + struct.pack("!I",sqn) + packet + bytes([0]) + bytes([packet_type])
            
            if hash_size !=0:            
                hash = self.integ_function.get(integ_alg) 
                h = hmac.HMAC(integ_key,hash)
                h.update(new_ike_packet)
                hash = h.finalize()[0:hash_size]         
            else:
                hash = b''
                
            return new_ike_packet + hash            
 
        
        return None

    def encapsulate_ipsec(self,args):

        pipe_ike = args[0]
        socket_list = [self.tunnel, pipe_ike, self.socket_esp]
        encr_alg = None
        integ_alg = None
        sqn = 1

        # NAT-T keepalive (VoWiFi engine addition): behind NAT (docker bridge / home router) the
        # ESP-in-UDP:4500 flow has a conntrack/NAT mapping that the kernel drops after ~30-120s
        # of silence, after which inbound ESP from the ePDG can no longer reach us and the tunnel
        # goes silently dead on idle. strongSwan sends an RFC 3948 NAT-keepalive (a single 0xFF
        # byte to the peer's 4500) every ~20s to hold the mapping open; the upstream emulator
        # sends nothing. Wake the select() loop on a timer and emit the keepalive when idle in
        # NAT-traversal mode. (In raw-ESP mode there is no UDP flow, so no keepalive is needed.)
        keepalive_interval = float(os.environ.get("SWU_NATT_KEEPALIVE", "20") or 20)
        last_keepalive = time.time()

        while True:
            timeout = keepalive_interval if keepalive_interval > 0 else None
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [], timeout)
            if keepalive_interval > 0 and self.userplane_mode == NAT_TRAVERSAL and \
                    (time.time() - last_keepalive) >= keepalive_interval:
                try:
                    self.socket_nat.sendto(b'\xff', self.server_address_nat)
                except Exception:
                    pass
                last_keepalive = time.time()
            for sock in read_sockets:
                if sock == self.tunnel:
                    tap_packet = os.read(self.tunnel, 1514)

                    if encr_alg is not None:

                        encrypted_packet = self.encapsulate_esp_packet(tap_packet,encr_alg,encr_key,integ_alg,integ_key,spi_resp,sqn)
                        if encrypted_packet is not None:
                            sqn += 1
                            if self.userplane_mode == ESP_PROTOCOL:
                                self.socket_esp.sendto(encrypted_packet, self.server_address_esp)
                            else:
                                self.socket_nat.sendto(encrypted_packet, self.server_address_nat)

                elif sock == pipe_ike:
                    pipe_packet = pipe_ike.recv()                     
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_DELETE_SA:
                        sys.exit()
                    elif decode_list[0] in (INTER_PROCESS_CREATE_SA, INTER_PROCESS_UPDATE_SA):
                        for i in decode_list[1]:
                            if i[0] == INTER_PROCESS_IE_ENCR_ALG: encr_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_ALG: integ_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_ENCR_KEY: encr_key = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_KEY: integ_key = i[1]                            
                            if i[0] == INTER_PROCESS_IE_SPI_RESP: spi_resp = i[1]
                    elif decode_list[0] == INTER_PROCESS_IKE and decode_list[1][0] == INTER_PROCESS_IE_IKE_MESSAGE: #not used for now. check 4 bytes zero if nat transversal
                        ike_message = decode_list[1][1]                    
                        self.socket_nat.sendto(ike_message, self.server_address_nat)
        
        return 0
    
    
    def decapsulate_ipsec(self,args):
        
        pipe_ike = args[0]
                
        socket_list = [self.socket_nat, pipe_ike, self.socket_esp]
        encr_alg = None
        integ_alg = None
        
        while True:
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            for sock in read_sockets:
                if sock == self.socket_nat:
                    packet, address = self.socket_nat.recvfrom(2000)
                    
                    if encr_alg is not None:
                        if packet[0:4] == b'\x00\x00\x00\x00': #is ike message
                            inter_process_list_ike_message = [INTER_PROCESS_IKE,[(INTER_PROCESS_IE_IKE_MESSAGE, packet)]]
                            pipe_ike.send(self.encode_inter_process_protocol(inter_process_list_ike_message))
                            
                        elif packet[0:4] == spi_init:
                           
                            if encr_alg is not None:
                                decrypted_packet = self.decapsulate_esp_packet(packet,encr_alg,encr_key,integ_alg,integ_key)
                                if decrypted_packet is not None:
                                    
                                    os.write(self.tunnel,decrypted_packet)
                        
                elif sock == self.socket_esp:
                    packet, address = self.socket_esp.recvfrom(2000)
                    if encr_alg is not None:
                        if packet[20:24] == spi_init:
                            
                            if encr_alg is not None:
                                decrypted_packet = self.decapsulate_esp_packet(packet[20:],encr_alg,encr_key,integ_alg,integ_key)
                                if decrypted_packet is not None:
                                    
                                    os.write(self.tunnel,decrypted_packet)
                        
               
                elif sock == pipe_ike:
                    pipe_packet = pipe_ike.recv()                     
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_DELETE_SA:
                        sys.exit()
                    elif decode_list[0] in (INTER_PROCESS_CREATE_SA, INTER_PROCESS_UPDATE_SA):
                        for i in decode_list[1]:
                            if i[0] == INTER_PROCESS_IE_ENCR_ALG: encr_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_ALG: integ_alg = i[1]
                            if i[0] == INTER_PROCESS_IE_ENCR_KEY: encr_key = i[1]
                            if i[0] == INTER_PROCESS_IE_INTEG_KEY: integ_key = i[1]                            
                            if i[0] == INTER_PROCESS_IE_SPI_INIT: spi_init = i[1]


        return 0

    def decapsulate_esp_packet(self,packet,encr_alg,encr_key,integ_alg,integ_key):       
    
        if encr_alg in (ENCR_AES_CBC,):
            vector = packet[8:24]
            hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
            hash_data = packet[-hash_size:]
        
            encrypted_data = packet[24:len(packet)-hash_size]
        
            cipher = Cipher(algorithms.AES(encr_key), modes.CBC(vector))            
            decryptor = cipher.decryptor()
            
            uncipher_data = decryptor.update(encrypted_data) + decryptor.finalize()
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0:-padding_length-2]

            return uncipher_packet
            
        elif encr_alg in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):
            if encr_alg == ENCR_AES_GCM_8: mac_length = 8
            if encr_alg == ENCR_AES_GCM_12: mac_length = 12
            if encr_alg == ENCR_AES_GCM_16: mac_length = 16
            
            aad = packet[0:8]            
            cipher = AES.new(encr_key[:-4], AES.MODE_GCM, nonce=encr_key[-4:] + packet[8:16],mac_len=mac_length)
            cipher.update(aad)

            uncipher_data = cipher.decrypt_and_verify(packet[16:-mac_length],packet[-mac_length:])                      
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0:-padding_length-2]                               
                     
            return uncipher_packet

        elif encr_alg in (ENCR_NULL,):
            hash_size = self.integ_key_truncated_len_bytes.get(integ_alg)
            hash_data = packet[-hash_size:]
        
            uncipher_data = packet[8:len(packet)-hash_size]
            padding_length = uncipher_data[-2]
            uncipher_packet = uncipher_data[0:-padding_length-2]

            return uncipher_packet

        return None
        
    def decode_inter_process_protocol(self,packet):
        try:
            ie_list = []
            message = packet[0]
            position = 3
            while position < len(packet):
                if packet[position+1] == 0 and packet[position+2] == 1:
                    ie_list.append((packet[position], packet[position+3]))
                else:
                    ie_list.append((packet[position], packet[position+3:position+3+packet[position+1]*256+packet[position+2]])) 
                position += 3+packet[position+1]*256+packet[position+2]
            return [message, ie_list]
        except:
            return [None,None]   



    def encode_inter_process_protocol(self,message):
        packet = b''
        for i in message[1]: 
            if type(i[1]) is int:
                packet += bytes([i[0]]) + b'\x00\x01' + bytes([i[1]])
            else:
                packet += bytes([i[0]]) + struct.pack("!H",len(i[1])) + i[1]
                
        packet = bytes([message[0]]) + struct.pack("!H",len(packet)) + packet        
        return packet
       
       
       
#### AUX FUNCTIONS RELATED TO STATES OR MESSAGES

    def get_eap_aka_attribute_value(self,list,id):
        for i in list:
           if i[0] == id: return i[1]
        return None

    def get_cp_attribute_value(self,list,id):
        return_list = []
        for i in list:
           if i[0] == id: return_list.append(i[1])
        return return_list

    def set_sa_negotiated(self,num):
        sa_negotiated = self.sa_list[num-1]
        self.sa_list_negotiated = [self.sa_list[num-1]]
        
        #default values
        self.negotiated_integrity_algorithm = NONE
        self.negotiated_encryption_algorithm = ENCR_NULL
        self.negotiated_encryption_algorithm_key_size = 0        
          
        for i in sa_negotiated[1:]:
            if i[0] == ENCR: 
                self.negotiated_encryption_algorithm = i[1]
                if self.negotiated_encryption_algorithm != ENCR_NULL: 
                    self.negotiated_encryption_algorithm_key_size = i[2][1]
            if i[0] == PRF: self.negotiated_prf = i[1]
            if i[0] == INTEG: self.negotiated_integrity_algorithm = i[1]            
            if i[0] == D_H: self.negotiated_diffie_hellman_group = i[1]            
   
    def remove_sa_from_list(self,accepted_dh_group): 
        new_sa_list = []
        for p in self.sa_list:
            for i in p:
                if i[0] == D_H and i[1] == accepted_dh_group:  
                    new_sa_list.append(p)
                    break              
        self.sa_list = new_sa_list
        

    def set_sa_negotiated_child(self,num):
        sa_negotiated = self.sa_list_child[num-1]
        self.spi_init_child = self.sa_spi_list[num-1]
        self.sa_list_negotiated_child = [self.sa_list_child[num-1]]
        
        #default values
        self.negotiated_integrity_algorithm_child = NONE
        self.negotiated_encryption_algorithm_child = ENCR_NULL
        self.negotiated_encryption_algorithm_key_size_child = 0
        
        for i in sa_negotiated[1:]:
            if i[0] == ENCR: 
                self.negotiated_encryption_algorithm_child = i[1]
                if self.negotiated_encryption_algorithm_child != ENCR_NULL:                
                    self.negotiated_encryption_algorithm_key_size_child = i[2][1]
            if i[0] == ESN: self.negotiated_esn_child = i[1]
            if i[0] == INTEG: self.negotiated_integrity_algorithm_child = i[1]            
            if i[0] == D_H: self.negotiated_diffie_hellman_group_child = i[1]            
   
    def generate_keying_material_child(self):
        
        STREAM = self.nounce + self.nounce_received
        
        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm_child) 
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size_child//8
        
        #exception for GCM since we need extra 4 bytes for SALT
        if self.negotiated_encryption_algorithm_child in (ENCR_AES_GCM_8, ENCR_AES_GCM_12, ENCR_AES_GCM_16):
            ENCR_KEY_SIZE += 4    
        
        KEY_LENGHT_TOTAL = 2*AUTH_KEY_SIZE + 2*ENCR_KEY_SIZE
        KEYMAT = self.prf_plus(self.negotiated_prf,self.SK_D,STREAM,KEY_LENGHT_TOTAL)
        
        self.SK_IPSEC_EI = KEYMAT[0:ENCR_KEY_SIZE]
        self.SK_IPSEC_AI = KEYMAT[ENCR_KEY_SIZE:ENCR_KEY_SIZE+AUTH_KEY_SIZE]
        self.SK_IPSEC_ER = KEYMAT[ENCR_KEY_SIZE+AUTH_KEY_SIZE:2*ENCR_KEY_SIZE+AUTH_KEY_SIZE]
        self.SK_IPSEC_AR = KEYMAT[2*ENCR_KEY_SIZE+AUTH_KEY_SIZE:2*ENCR_KEY_SIZE+2*AUTH_KEY_SIZE]
               
        
        print('SK_IPSEC_AI',toHex(self.SK_IPSEC_AI))
        print('SK_IPSEC_AR',toHex(self.SK_IPSEC_AR))
        print('SK_IPSEC_EI',toHex(self.SK_IPSEC_EI))
        print('SK_IPSEC_ER',toHex(self.SK_IPSEC_ER))        

        self.print_esp_sa()        
        
    def generate_keying_material(self):

        hash = self.prf_function.get(self.negotiated_prf) 
        h = hmac.HMAC(self.nounce + self.nounce_received,hash)
        h.update(self.dh_shared_key)
        SKEYSEED = h.finalize() 
        print('SKEYSEED',toHex(SKEYSEED))
        
        STREAM = self.nounce + self.nounce_received + self.ike_spi_initiator + self.ike_spi_responder
        print('STREAM',toHex(STREAM))
        
        PRF_KEY_SIZE = self.prf_key_len_bytes.get(self.negotiated_prf)
        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm) 
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size//8
        
        KEY_LENGHT_TOTAL = 3*PRF_KEY_SIZE + 2*AUTH_KEY_SIZE + 2*ENCR_KEY_SIZE

        KEY_STREAM = self.prf_plus(self.negotiated_prf,SKEYSEED,STREAM,KEY_LENGHT_TOTAL)
        
        self.SK_D  = KEY_STREAM[0:PRF_KEY_SIZE]
        self.SK_AI = KEY_STREAM[PRF_KEY_SIZE:PRF_KEY_SIZE+AUTH_KEY_SIZE]
        self.SK_AR = KEY_STREAM[PRF_KEY_SIZE+AUTH_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE]
        self.SK_EI = KEY_STREAM[PRF_KEY_SIZE+2*AUTH_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE+ENCR_KEY_SIZE]
        self.SK_ER = KEY_STREAM[PRF_KEY_SIZE+2*AUTH_KEY_SIZE+ENCR_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE]
        self.SK_PI = KEY_STREAM[PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE:2*PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE]
        self.SK_PR = KEY_STREAM[2*PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE:3*PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE]

        print('SK_D',toHex(self.SK_D))
        print('SK_AI',toHex(self.SK_AI))
        print('SK_AR',toHex(self.SK_AR))
        print('SK_EI',toHex(self.SK_EI))
        print('SK_ER',toHex(self.SK_ER))
        print('SK_PI',toHex(self.SK_PI))
        print('SK_PR',toHex(self.SK_PR))

        self.print_ikev2_decryption_table()          
        
    def generate_new_ike_keying_material(self):
        
        self.SK_D_old  = self.SK_D 
        self.SK_AI_old = self.SK_AI
        self.SK_AR_old = self.SK_AR
        self.SK_EI_old = self.SK_EI
        self.SK_ER_old = self.SK_ER
        self.SK_PI_old = self.SK_PI
        self.SK_PR_old = self.SK_PR

        hash = self.prf_function.get(self.negotiated_prf) 
        h = hmac.HMAC(self.SK_D,hash)
        h.update(self.dh_shared_key + self.nounce + self.nounce_received)
        SKEYSEED = h.finalize() 
        print('SKEYSEED',toHex(SKEYSEED))
        
        STREAM = self.nounce + self.nounce_received + self.ike_spi_initiator + self.ike_spi_responder    
        
        print('STREAM',toHex(STREAM))        
        PRF_KEY_SIZE = self.prf_key_len_bytes.get(self.negotiated_prf)
        AUTH_KEY_SIZE = self.integ_key_len_bytes.get(self.negotiated_integrity_algorithm) 
        ENCR_KEY_SIZE = self.negotiated_encryption_algorithm_key_size//8
        
        KEY_LENGHT_TOTAL = PRF_KEY_SIZE + 2*AUTH_KEY_SIZE + 2*ENCR_KEY_SIZE

        KEY_STREAM = self.prf_plus(self.negotiated_prf,SKEYSEED,STREAM,KEY_LENGHT_TOTAL)
        
        self.SK_D  = KEY_STREAM[0:PRF_KEY_SIZE]
        self.SK_AI = KEY_STREAM[PRF_KEY_SIZE:PRF_KEY_SIZE+AUTH_KEY_SIZE]
        self.SK_AR = KEY_STREAM[PRF_KEY_SIZE+AUTH_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE]
        self.SK_EI = KEY_STREAM[PRF_KEY_SIZE+2*AUTH_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE+ENCR_KEY_SIZE]
        self.SK_ER = KEY_STREAM[PRF_KEY_SIZE+2*AUTH_KEY_SIZE+ENCR_KEY_SIZE:PRF_KEY_SIZE+2*AUTH_KEY_SIZE+2*ENCR_KEY_SIZE]
   
        print('SK_D',toHex(self.SK_D))
        print('SK_AI',toHex(self.SK_AI))
        print('SK_AR',toHex(self.SK_AR))
        print('SK_EI',toHex(self.SK_EI))
        print('SK_ER',toHex(self.SK_ER))

        self.print_ikev2_decryption_table()  
        
    def prf_plus(self,algorithm,key,stream,size):
        hash = self.prf_function.get(algorithm)  
        t = b''
        t_total = b''
        iter = 1
        while len(t_total)<size:
            h = hmac.HMAC(key,hash)
            h.update(t + stream + bytes([iter]))
            t = h.finalize()
            t_total += t
            iter += 1
    
        return t_total[0:size]
 

    def sha1_nat_source(self,print_info=True):
        digest = hashes.Hash(hashes.SHA1())
        if self.userplane_mode == ESP_PROTOCOL:
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET,self.source_address) + struct.pack('!H',self.port))    
        else: #NAT_TRAVERSAL
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET,self.source_address) + struct.pack('!H',self.port_nat))
        hash = digest.finalize()
        if print_info == True: print('NAT SOURCE',toHex(hash))
        return hash

    def sha1_nat_destination(self, print_info=True):
        digest = hashes.Hash(hashes.SHA1())
        if self.userplane_mode == ESP_PROTOCOL:
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET,self.epdg_address) + struct.pack('!H',self.port))    
        else: #NAT_TRAVERSAL
            digest.update(self.ike_spi_initiator + self.ike_spi_responder + socket.inet_pton(socket.AF_INET,self.epdg_address) + struct.pack('!H',self.port_nat))
        hash = digest.finalize()
        if print_info == True: print('NAT DESTINATION',toHex(hash))
        return hash

 
#### MESSAGES ####

    def create_IKE_SA_INIT(self, same_spi = False, cookie = False):
        #create SPIi
        if same_spi == False: self.ike_spi_initiator = self.return_random_bytes(8)
        self.ike_spi_responder = (0).to_bytes(8,'big')
        if cookie == False:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, IKE_SA_INIT, (0,0,1), self.message_id_request)
            payload = b''
        else:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, IKE_SA_INIT, (0,0,1), self.message_id_request)
            payload = self.encode_generic_payload_header(SA,0,self.encode_payload_type_n(RESERVED,b'',COOKIE,self.cookie_received_bytes)) 
            
        payload += self.encode_generic_payload_header(KE,0,self.encode_payload_type_sa(self.sa_list))        
        
        payload += self.encode_generic_payload_header(NINR,0,self.encode_payload_type_ke())  
        if self.check_nat == False:
            if cookie == True:
                payload += self.encode_generic_payload_header(NONE,0,self.nounce)  
            else:            
                payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_ninr())        
        else:
            if cookie == True:
                payload += self.encode_generic_payload_header(N,0,self.nounce)             
            else:
                payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_ninr()) 
                
            payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_n(RESERVED,b'',NAT_DETECTION_SOURCE_IP,self.sha1_nat_source())) 
            payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(RESERVED,b'',NAT_DETECTION_DESTINATION_IP,self.sha1_nat_destination())) 
        packet = self.set_ike_packet_length(header+payload)        
        return packet

    def create_IKE_AUTH(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, IDI, 2, 0, IKE_AUTH, (0,0,1), self.message_id_request)
        payload = self.encode_generic_payload_header(IDR,0,self.encode_payload_type_idi())
        payload += self.encode_generic_payload_header(CP,0,self.encode_payload_type_idr())        
        payload += self.encode_generic_payload_header(SA,0,self.encode_payload_type_cp())   
        payload += self.encode_generic_payload_header(TSI,0,self.encode_payload_type_sa(self.sa_list_child))         
        payload += self.encode_generic_payload_header(TSR,0,self.encode_payload_type_tsi())          
        payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_tsr())
        # VoWiFi engine addition: INITIAL_CONTACT tells the ePDG this is a fresh attach so it
        # deletes any older IKE SA it still holds for this subscriber (e.g. after a hard kill),
        # avoiding single-SA-per-subscriber conflicts on reconnect. Standard IKEv2 behaviour
        # (strongSwan sends it too).
        payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_n(RESERVED,b'',INITIAL_CONTACT))
        payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(RESERVED,b'',EAP_ONLY_AUTHENTICATION))                
        packet = self.set_ike_packet_length(header+payload)        
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)     
        return encrypted_and_integrity_packet

    def create_IKE_AUTH_EAP_IDENTITY(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, EAP, 2, 0, IKE_AUTH, (0,0,1), self.message_id_request)        
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_eap())        
        packet = self.set_ike_packet_length(header+payload)        
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet


    def create_IKE_AUTH_2(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, EAP, 2, 0, IKE_AUTH, (0,0,1), self.message_id_request)
        if self.device_identity_requested:
            payload  = self.encode_generic_payload_header(N,0,self.encode_payload_type_eap())
            payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(RESERVED,b'',DEVICE_IDENTITY,self.encode_device_identity_notification_data()))
            self.device_identity_requested = False
        else:
            payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_eap())
        packet = self.set_ike_packet_length(header+payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def create_IKE_AUTH_3(self):
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, AUTH, 2, 0, IKE_AUTH, (0,0,1), self.message_id_request)
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_auth(SHARED_KEY_MESSAGE_INTEGRITY_CODE))
        packet = self.set_ike_packet_length(header+payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet
        

    def answer_INFORMATIONAL_delete(self):
        if self.old_ike_message_received == True:    
            header = self.encode_header(self.ike_spi_initiator_old, self.ike_spi_responder_old, NONE, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])        
        else:           
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, NONE, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])        
        
        packet = self.set_ike_packet_length(header)        
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet

    def answer_INFORMATIONAL_delete_CHILD(self,protocol,spi_list = b''):

        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, D, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])

        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_d(protocol,spi_list))
        packet = self.set_ike_packet_length(header+payload)

        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)
        return encrypted_and_integrity_packet

    def answer_INFORMATIONAL_empty(self):
        """Empty INFORMATIONAL response (no payloads). Used to acknowledge a Dead-Peer-Detection
        liveness check (RFC 7296 clause 2.4) and any ePDG-initiated INFORMATIONAL request we do
        not need to add payloads to. Mirrors the responder SPIs/message-id of the request."""
        if self.old_ike_message_received == True:
            header = self.encode_header(self.ike_spi_initiator_old, self.ike_spi_responder_old, NONE, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])
        else:
            header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, NONE, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])
        packet = self.set_ike_packet_length(header)
        return self.encode_payload_type_sk(packet)

    def answer_INFORMATIONAL_device_identity(self):
        """INFORMATIONAL response carrying a DEVICE_IDENTITY Notify (3GPP TS 24.302 clause 7.2.6):
        the ePDG asked for the Mobile Equipment Identity after tunnel establishment via an
        INFORMATIONAL request with an empty-value DEVICE_IDENTITY notify; answer with our
        IMEISV (preferred) or IMEI."""
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(RESERVED,b'',DEVICE_IDENTITY,self.encode_device_identity_notification_data()))
        packet = self.set_ike_packet_length(header+payload)
        return self.encode_payload_type_sk(packet)

    def answer_INFORMATIONAL_notify(self, notify_message_type, notification_data=b''):
        """INFORMATIONAL response carrying a single arbitrary Notify. Generic helper for
        acknowledging ePDG-initiated status requests where we must echo a specific notify."""
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, INFORMATIONAL, (1,0,1), self.ike_decoded_header['message_id'])
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(RESERVED,b'',notify_message_type,notification_data))
        packet = self.set_ike_packet_length(header+payload)
        return self.encode_payload_type_sk(packet)

    def log_notify_error(self, code, context=""):
        """Log a received Private/RFC7296 error-type Notify with its friendly name + description
        (3GPP TS 24.302 Table 8.1.2.2-1). Central place so every auth-flow error site renders the
        numeric code in human terms instead of a bare integer."""
        name = notify_name(code)
        desc = notify_describe(code)
        where = (" during %s" % context) if context else ""
        if desc:
            swu_log("received ERROR Notify%s: %s (%d) - %s" % (where, name, code, desc))
        else:
            swu_log("received ERROR Notify%s: %s (%d)" % (where, name, code))

    @staticmethod
    def decode_backoff_timer(value_byte):
        """Decode a one-octet GPRS timer 3 value (3GPP TS 24.008 clause 10.5.7.4a) carried in a
        BACKOFF_TIMER Notify (clause 8.2.9.1). Returns (seconds_or_None, human_text).
        Unit is bits 6-8, timer value is bits 1-5. Unit 7 = deactivated/no timer."""
        unit = (value_byte >> 5) & 0x07
        val = value_byte & 0x1F
        if unit == 0:   return (val * 2,      "%d s" % (val * 2))          # 2 s increments
        if unit == 1:   return (val * 60,     "%d min" % val)              # 1 min increments
        if unit == 2:   return (val * 600,    "%d min" % (val * 10))       # 10 min increments
        if unit == 3:   return (val * 3600,   "%d h" % val)                # 1 hour increments
        if unit == 4:   return (val * 36000,  "%d h" % (val * 10))         # 10 hour increments
        if unit == 5:   return (val * 120,    "%d min" % (val * 2))        # 2 min increments  (release 10+)
        if unit == 6:   return (val * 30,     "%d s" % (val * 30))         # 30 s increments
        return (None, "deactivated")                                       # unit == 7

    def handle_INFORMATIONAL_request(self):
        """Handle an ePDG-initiated INFORMATIONAL *request* received while CONNECTED that is NOT
        a DELETE (those go through state_delete). Covers:
          - Dead-Peer-Detection liveness check (empty request)  -> empty response  [RFC 7296 2.4]
          - DEVICE_IDENTITY request (empty value)               -> answer IMEISV/IMEI [TS 24.302 7.2.6]
          - REACTIVATION_REQUESTED_CAUSE (usually with DELETE, handled there)
          - any other status notify (bearer mod, PTI, ...)      -> acknowledge with empty response
        Every payload is logged with its friendly name so operators can see what the ePDG asked.
        Returns True if a response was sent, False if the message was not an INFORMATIONAL request
        we recognised (caller may fall through)."""
        device_identity_requested = False
        saw_notify = False
        payload_names = []
        for i in self.decoded_payload[0][1]:
            if i[0] == N:
                saw_notify = True
                ntype = i[1][1]
                ndata = i[1][3]
                payload_names.append(notify_name(ntype))
                if ntype == DEVICE_IDENTITY:
                    # Identity Value empty (only the 1-byte identity type present, or nothing) =>
                    # the ePDG is asking us for the ME identity.
                    id_type = ndata[-1] if ndata else None
                    # notification_data layout for a request is [len(2)][identity type(1)] with no
                    # value; treat <=3 bytes as "value empty" -> a request, not an echo of ours.
                    if ndata is None or len(ndata) <= 3:
                        device_identity_requested = True
                        # honour the requested identity type (0x01 IMEI / 0x02 IMEISV); default IMEISV
                        self.device_identity_type = id_type if id_type in (0x01, 0x02) else 0x02
                elif ntype == BACKOFF_TIMER:
                    secs, txt = (None, "")
                    if ndata and len(ndata) >= 1:
                        secs, txt = self.decode_backoff_timer(ndata[-1])
                    swu_log("INFORMATIONAL: BACKOFF_TIMER = %s" % (txt or "?"))

        # A DEVICE_IDENTITY request wins: answer with our identity.
        if device_identity_requested:
            swu_log("INFORMATIONAL request: ePDG asked for DEVICE_IDENTITY; answering")
            self.send_data(self.answer_INFORMATIONAL_device_identity())
            return True

        if saw_notify:
            swu_log("INFORMATIONAL request (status: %s); acknowledging" % ", ".join(payload_names))
            self.send_data(self.answer_INFORMATIONAL_empty())
            return True

        # No payloads at all => Dead-Peer-Detection liveness probe. Must answer or the ePDG tears
        # the tunnel down for being unresponsive.
        swu_log("INFORMATIONAL request (DPD liveness check); answering")
        self.send_data(self.answer_INFORMATIONAL_empty())
        return True


    def create_INFORMATIONAL_delete(self,protocol,spi_list = b''):
        
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, D, 2, 0, INFORMATIONAL, (0,0,1), self.message_id_request)        
        
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_d(protocol,spi_list))        
        packet = self.set_ike_packet_length(header+payload)        
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet


    def answer_CREATE_CHILD_SA(self):
        
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (1,0,1), self.ike_decoded_header['message_id'])        
       
        payload = self.encode_generic_payload_header(KE,0,self.encode_payload_type_sa(self.sa_list_create_child_sa))
        payload += self.encode_generic_payload_header(NINR,0,self.encode_payload_type_ke())  
        payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_ninr())          
        packet = self.set_ike_packet_length(header+payload)   
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet        


    def answer_NOTIFY_NO_PROPOSAL_CHOSEN(self):
        
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, N, 2, 0, CREATE_CHILD_SA, (1,0,1), self.ike_decoded_header['message_id'])        
        
        payload = self.encode_generic_payload_header(NONE,0,self.encode_payload_type_n(IKE,b'',NO_PROPOSAL_CHOSEN))          
        packet = self.set_ike_packet_length(header+payload)   
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet  


    def create_CREATE_CHILD_SA(self, lowest = 0):
       
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (0,0,1), self.message_id_request)        
        
        payload = self.encode_generic_payload_header(KE,0,self.encode_payload_type_sa(self.sa_list_create_child_sa))
        payload += self.encode_generic_payload_header(NINR,0,self.encode_payload_type_ke())  
        payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_ninr(lowest))          
        packet = self.set_ike_packet_length(header+payload)   
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet   


    def create_CREATE_CHILD_SA_CHILD(self,lowest = 0):
        
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (0,0,1), self.message_id_request)        
          
        payload = self.encode_generic_payload_header(NINR,0,self.encode_payload_type_sa(self.sa_list_create_child_sa_child)) 
        payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_ninr(lowest))          
        payload += self.encode_generic_payload_header(TSI,0,self.encode_payload_type_n(ESP,self.spi_init_child,REKEY_SA))
        payload += self.encode_generic_payload_header(TSR,0,self.encode_payload_type_tsi())          
        payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_tsr())   
        
        packet = self.set_ike_packet_length(header+payload)   
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet  

    def answer_CREATE_CHILD_SA_CHILD(self,lowest = 0):
        
        header = self.encode_header(self.ike_spi_initiator, self.ike_spi_responder, SA, 2, 0, CREATE_CHILD_SA, (1,0,1), self.ike_decoded_header['message_id'])        
        
        payload = self.encode_generic_payload_header(NINR,0,self.encode_payload_type_sa(self.sa_list_create_child_sa_child)) 
        payload += self.encode_generic_payload_header(N,0,self.encode_payload_type_ninr(lowest))          
        payload += self.encode_generic_payload_header(TSI,0,self.encode_payload_type_n(ESP,self.spi_init_child,REKEY_SA))
        payload += self.encode_generic_payload_header(TSR,0,self.encode_payload_type_tsi())          
        payload += self.encode_generic_payload_header(NONE,0,self.encode_payload_type_tsr())   
        
        packet = self.set_ike_packet_length(header+payload)   
        
        encrypted_and_integrity_packet = self.encode_payload_type_sk(packet)                       
        return encrypted_and_integrity_packet  



#### STATES ####

    def state_1(self, retry = False, cookie = False): #Send IKE_SA_INIT and process answer
        self.message_id_request = 0
        
        packet = self.create_IKE_SA_INIT(retry, cookie)
        
        self.AUTH_SA_INIT_packet = packet #needed for AUTH Payload in state 4
        
        self.send_data(packet)
        print('sending IKE_SA_INIT')
        
        try:
        #if True:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)  
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True: break                
                else:                 
                    packet, address = self.socket_nat.recvfrom(2000)                     
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True: break                     
                
        except: #timeout          
            return TIMEOUT,'TIMEOUT'
        
        
        if self.ike_decoded_header['exchange_type'] == IKE_SA_INIT:
            print('received IKE_SA_INIT')        
            for i in self.decoded_payload:
                if i[0] == NINR:
                    self.nounce_received = i[1][0]
                
                elif i[0] == SA:
                    proposal = i[1][0]
                    protocol_id = i[1][1]
                    if protocol_id == IKE:
                        self.set_sa_negotiated(proposal)
                    else:
                        return MANDATORY_INFORMATION_MISSING,'MANDATORY_INFORMATION_MISSING'
                
                elif i[0] == KE:
                    dh_peer_public_key_bytes = i[1][1]
                    self.dh_calculate_shared_key(dh_peer_public_key_bytes)
                
                elif i[0] == N:    #protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] == INVALID_KE_PAYLOAD:
                        accepted_dh_group = struct.unpack("!H", i[1][3])[0]
                        self.remove_sa_from_list(accepted_dh_group)
                        return REPEAT_STATE,'INVALID_KE_PAYLOAD'
                    elif i[1][1]<16384: #error
                        return OTHER_ERROR,str(i[1][1])
                        
                    elif i[1][1] == COOKIE:
                        self.cookie = True
                        self.cookie_received_bytes = i[1][3]
                        return REPEAT_STATE_COOKIE, 'REPEAT SA_INIT WITH COOKIE'
                        
                    elif i[1][1] == NAT_DETECTION_DESTINATION_IP:
                        received_nat_detection_destination = i[1][3]
                        print('NAT DESTINATION RECEIVED',toHex(received_nat_detection_destination))
                        calculated_nat_detection_destination = self.sha1_nat_source(False)
                        print('NAT DESTINATION CALCULATED',toHex(calculated_nat_detection_destination))
                        if received_nat_detection_destination != calculated_nat_detection_destination:
                            self.userplane_mode = NAT_TRAVERSAL
                        
                    elif i[1][1] == NAT_DETECTION_SOURCE_IP:
                        received_nat_detection_source = i[1][3]
                        print('NAT SOURCE RECEIVED',toHex(received_nat_detection_source))
                        calculated_nat_detection_source = self.sha1_nat_destination(False)
                        print('NAT SOURCE CALCULATED',toHex(calculated_nat_detection_source))
                        if received_nat_detection_source != calculated_nat_detection_source:
                            self.userplane_mode = NAT_TRAVERSAL
                        
            self.generate_keying_material()
            
            print('IKE SPI INITIATOR',toHex(self.ike_spi_initiator))
            print('IKE SPI RESPONDER',toHex(self.ike_spi_responder))
            
            return OK,''
        else:
            return DECODING_ERROR,'DECODING_ERROR'


    def state_2(self, retry = False):
        self.message_id_request += 1
        if retry == False:
            packet = self.create_IKE_AUTH()
        else:
            packet = self.create_IKE_AUTH_EAP_IDENTITY()
        self.send_data(packet)
        print('sending IKE_AUTH (1)')        

        try:
        
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)  
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True: break                
                else:
                    packet, address = self.socket_nat.recvfrom(2000)  
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True: break                     
                
        except: #timeout
            return TIMEOUT,'TIMEOUT'        
        
        eap_received = False
        if self.ike_decoded_header['exchange_type'] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print('received IKE_AUTH (1)')             
            for i in self.decoded_payload[0][1]:
                
                if i[0] == N:    #protocol_id, notify_message_type, spi, notification_data
                    if i[1][1] == DEVICE_IDENTITY:
                        self.device_identity_requested = True
                        self.device_identity_type = i[1][3][-1] if i[1][3] else None

                    elif i[1][1]<16384: #error
                        code = i[1][1]
                        if code == AUTHENTICATION_FAILED:
                            # The ePDG rejected our identity at IKE_AUTH *before* sending any
                            # EAP-AKA challenge — the SIM was never queried. This is an AAA/HSS
                            # decision, NOT a SIM/PIN problem. Typical causes: the line is not
                            # subscribed/provisioned for VoWiFi, or the ePDG refuses attaches
                            # from this (foreign) source IP. Nothing tunable on our side fixes it.
                            swu_log("IKE_AUTH rejected with AUTHENTICATION_FAILED before any "
                                    "EAP-AKA challenge (SIM not queried). The ePDG/AAA refused "
                                    "the identity: the SIM is likely not provisioned for VoWiFi, "
                                    "or the ePDG blocks this source IP/region. NAI=%s APN(IDr)=%s" %
                                    (self.identification_initiator[1] if self.identification_initiator else "?",
                                     self.identification_responder[1] if self.identification_responder else "?"))
                        else:
                            self.log_notify_error(code, "IKE_AUTH")
                        return OTHER_ERROR,str(code)
   
                    if i[1][0] in (EAP_REQUEST,) and i[1][2] in (EAP_AKA,):
                        if i[1][3] in (AKA_Challenge, AKA_Reauthentication):
                            
                            eap_received = True
                            
                            RAND = self.get_eap_aka_attribute_value(i[1][4],AT_RAND)
                            AUTN = self.get_eap_aka_attribute_value(i[1][4],AT_AUTN)
                            MAC = self.get_eap_aka_attribute_value(i[1][4],AT_MAC)
                            
                            VECTOR =  self.get_eap_aka_attribute_value(i[1][4],AT_IV)
                            ENCR_DATA =  self.get_eap_aka_attribute_value(i[1][4],AT_ENCR_DATA)
                           
                            self.eap_identifier = i[1][1]
                                                     
                            if (RAND is not None and AUTN is not None) or (VECTOR is not None and ENCR_DATA is not None):
                                if RAND is not None and AUTN is not None:
                                    if self.sqn is not None and retry == False:
                                        auts = return_auts(toHex(RAND), toHex(AUTN),self.ki,self.op,self.opc, self.sqn)
                                        eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex('0018170400000404') + auts
                                        self.eap_payload_response = eap_payload_response
                                        return REPEAT_STATE,'SYNC FAILURE'

                                    else:
                                        self.current_counter = None
                                        print('RAND',toHex(RAND))
                                        print('AUTN',toHex(AUTN))
                                        print('MAC',toHex(MAC))
                                        
                                        res,ck,ik = return_res_ck_ik(self.com_port,toHex(RAND),toHex(AUTN),self.ki,self.op,self.opc)
                                        
                                        if res is not None and ck is None and ik is None:
                                            #RES is AUTS
                                            auts, res = res, None
                                            print('AUTS', auts)
                                            eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex('0018170400000404') + fromHex(auts)
                                            self.eap_payload_response = eap_payload_response
                                            return REPEAT_STATE,'SYNC FAILURE'
                                            
                                        else:    
                                            
                                            print('RES',res)
                                            print('CK',ck)
                                            print('IK',ik)
                                        
                                            self.RES, CK, IK = fromHex(res), fromHex(ck), fromHex(ik)
                                            self.KENCR, self.KAUT, self.MSK, self.EMSK, self.MK = self.eap_keys_calculation(CK,IK)
                                            print('KENCR',toHex(self.KENCR))
                                            print('KAUT',toHex(self.KAUT))
                                            print('MSK',toHex(self.MSK))
                                            print('EMSK',toHex(self.EMSK))
                                        
                                            # Calculate dynamic EAP payload with proper padding
                                            eap_payload_response = self.build_eap_aka_response(self.eap_identifier, self.RES)
                                        
                                            h = hmac.HMAC(self.KAUT,hashes.SHA1())
                                            h.update(eap_payload_response)
                                            hash = h.finalize()[0:16]  
                                            self.eap_payload_response = eap_payload_response[:-16] + hash
                                    
                                if VECTOR is not None and ENCR_DATA is not None:                                
                                    print('IV',toHex(VECTOR))
                                    print('ENCR_DATA',toHex(ENCR_DATA))
                                    
                                    cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(VECTOR))  
                                    decryptor = cipher.decryptor()
                                    uncipher_data = decryptor.update(ENCR_DATA) + decryptor.finalize()
                                    print('DECRYPTED DATA',toHex(uncipher_data))
                                    eap_attributes = self.decode_eap_attributes(uncipher_data)
                                    print(eap_attributes)
                                    NEXT_REAUTH_ID = self.get_eap_aka_attribute_value(eap_attributes,AT_NEXT_REAUTH_ID)
                                    COUNTER = self.get_eap_aka_attribute_value(eap_attributes,AT_COUNTER)
                                    NONCE_S = self.get_eap_aka_attribute_value(eap_attributes,AT_NONCE_S)
                                    
                                    
                                    
                                    if NEXT_REAUTH_ID is not None: 
                                        self.next_reauth_id = NEXT_REAUTH_ID.decode('utf-8')
                                        print('NEXT REAUTH ID',self.next_reauth_id)
                                    else:
                                        #should use permanent identity next 
                                        self.next_reauth_id = None
                                        
                                        
                                    if COUNTER is not None and NONCE_S is not None:
                                        ERROR = False
                                        if self.current_counter is None:
                                            self.current_counter = COUNTER
                                        else:
                                            if COUNTER > self.current_counter:
                                                self.current_counter = COUNTER
                                                
                                            else:
                                                #error: include AT_COUNTER_TOO_SMALL
                                                ERROR = True
                                                
                                                                            
                                        #XKEY' = SHA1(Identity|counter|NONCE_S| MK)
                                        self.MSK, self.EMSK, self.XKEY = self.eap_keys_calculation_fast_reauth(COUNTER, NONCE_S)
                                        print('MSK',toHex(self.MSK))
                                        print('EMSK',toHex(self.EMSK))                     
                                        
                                        vector = self.return_random_bytes(16)
                                        at_iv = bytes([AT_IV]) + fromHex('050000') + vector
                                        
                                        if ERROR == False:
                                            at_padding = bytes([AT_PADDING]) + fromHex('0300000000000000000000')
                                            at_counter = bytes([AT_COUNTER]) + b'\x01' + struct.pack('!H',COUNTER)
                                            at_counter_too_small = b''
                                        else:
                                            at_padding = bytes([AT_PADDING]) + fromHex('02000000000000')
                                            at_counter = bytes([AT_COUNTER]) + b'\x01' + struct.pack('!H',COUNTER)
                                            at_counter_too_small = bytes([AT_COUNTER_TOO_SMALL]) + b'\x01\x00\x00' 
                                            
                                        cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(vector)) 
                                        encryptor = cipher.encryptor()          
                                        cipher_data = encryptor.update(at_counter + at_counter_too_small + at_padding) + encryptor.finalize()                                        
                                        
                                        at_encr_data = bytes([AT_ENCR_DATA]) + fromHex('050000') + cipher_data
                                        length = struct.pack('!H',len(at_iv)+len(at_encr_data)+28)
                                        
                                        eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + length + fromHex('170d0000') + at_iv + at_encr_data + fromHex('0b050000' + 16*'00')
   
                                        h = hmac.HMAC(self.KAUT,hashes.SHA1())
                                        h.update(eap_payload_response + NONCE_S)
                                        hash = h.finalize()[0:16]  
                                        self.eap_payload_response = eap_payload_response[:-16] + hash
                                    
                            else:
                                return OTHER_ERROR,'NO RAND/AUTN IN EAP'
                        
                        elif i[1][3] in (AKA_Identity,):
                            
                      
                            if i[1][4][0][0] in (AT_ANY_ID_REQ, AT_IDENTITY):
                                self.eap_identifier = i[1][1]
                                identity = (
                                        '0'
                                        + self.imsi
                                        + '@nai.epc.mnc' + self.mnc
                                        + '.mcc' + self.mcc
                                        + '.3gppnetwork.org'
                                )
                                self.eap_payload_response = (
                                        bytes([2])
                                        + bytes([self.eap_identifier])
                                        + fromHex("004417050000")
                                        + self.encode_eap_at_identity(identity))

                                # update the EAP length
                                eap = bytearray(self.eap_payload_response)
                                eap_length = struct.pack('>H', len(eap))
                                eap[2] = eap_length[0]
                                eap[3] = eap_length[1]
                                self.eap_payload_response = bytes(eap)

                                return REPEAT_STATE,'EAP IDENTITY REQUESTED'


            if eap_received == True:
                return OK,''               
            else:
                return MANDATORY_INFORMATION_MISSING,'NO EAP PAYLOAD RECEIVED'              
            
        
    def state_3(self):
        self.message_id_request += 1
        packet = self.create_IKE_AUTH_2()
        self.send_data(packet)
        print('sending IKE_SA_AUTH (2)')        


        try:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)  
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True: break                
                else:
                    packet, address = self.socket_nat.recvfrom(2000)  
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True: break                     
                
        except: #timeout
            return TIMEOUT,'TIMEOUT'        
        
        
        eap_received = False
        if self.ike_decoded_header['exchange_type'] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print('received IKE_AUTH (2)')              
            for i in self.decoded_payload[0][1]:
                
                if i[0] == N:    #protocol_id, notify_message_type, spi, notification_data
                    if i[1][1]<16384: #error
                        self.log_notify_error(i[1][1], "IKE_AUTH")
                        return OTHER_ERROR,str(i[1][1])

                elif i[0] == EAP:
                    eap_received = True
                    if i[1][0] in (EAP_SUCCESS,):
                    
                        hash = self.prf_function.get(self.negotiated_prf) 
                        h = hmac.HMAC(self.SK_PI,hash)
                        h.update(bytes([self.identification_initiator[0]]) + b'\x00'*3 + self.identification_initiator[1].encode('utf-8'))
                        hash_result = h.finalize() 
                        self.AUTH_SA_INIT_packet += self.nounce_received + hash_result
                        
                        keypad = b'Key Pad for IKEv2'
                        h = hmac.HMAC(self.MSK,hash)
                        h.update(keypad)
                        hash_result = h.finalize() 
                        h = hmac.HMAC(hash_result,hash)
                        h.update(self.AUTH_SA_INIT_packet)
                        self.AUTH_payload = h.finalize()                        
                        
                    elif i[1][0] in (EAP_REQUEST,) and i[1][2] in (EAP_AKA,):
                        if i[1][3] in (AKA_Challenge,):
                            
                            RAND = self.get_eap_aka_attribute_value(i[1][4],AT_RAND)
                            AUTN = self.get_eap_aka_attribute_value(i[1][4],AT_AUTN)
                            MAC = self.get_eap_aka_attribute_value(i[1][4],AT_MAC)
                            
                            VECTOR =  self.get_eap_aka_attribute_value(i[1][4],AT_IV)
                            ENCR_DATA =  self.get_eap_aka_attribute_value(i[1][4],AT_ENCR_DATA)
                           
                            self.eap_identifier = i[1][1]
                                                     
                            if (RAND is not None and AUTN is not None) or (VECTOR is not None and ENCR_DATA is not None):
                                if RAND is not None and AUTN is not None:
                                    self.current_counter = None
                                    print('RAND',toHex(RAND))
                                    print('AUTN',toHex(AUTN))
                                    print('MAC',toHex(MAC))
                                    
                                    res,ck,ik = return_res_ck_ik(self.com_port,toHex(RAND),toHex(AUTN),self.ki,self.op,self.opc)
                                    print('RES',res)
                                    print('CK',ck)
                                    print('IK',ik)
                                    
                                    self.RES, CK, IK = fromHex(res), fromHex(ck), fromHex(ik)
                                    self.KENCR, self.KAUT, self.MSK, self.EMSK, self.MK = self.eap_keys_calculation(CK,IK)
                                    print('KENCR',toHex(self.KENCR))
                                    print('KAUT',toHex(self.KAUT))
                                    print('MSK',toHex(self.MSK))
                                    print('EMSK',toHex(self.EMSK))
                                    
                                    # Calculate dynamic EAP payload with proper padding
                                    eap_payload_response = self.build_eap_aka_response(self.eap_identifier, self.RES)
                                    
                                    h = hmac.HMAC(self.KAUT,hashes.SHA1())
                                    h.update(eap_payload_response)
                                    hash = h.finalize()[0:16]  
                                    self.eap_payload_response = eap_payload_response[:-16] + hash
                                
                                if VECTOR is not None and ENCR_DATA is not None:                                
                                    print('IV',toHex(VECTOR))
                                    print('ENCR_DATA',toHex(ENCR_DATA))
                                    
                                    cipher = Cipher(algorithms.AES(self.KENCR), modes.CBC(VECTOR))  
                                    decryptor = cipher.decryptor()
                                    uncipher_data = decryptor.update(ENCR_DATA) + decryptor.finalize()
                                    print('DECRYPTED DATA',toHex(uncipher_data))
                                    eap_attributes = self.decode_eap_attributes(uncipher_data)
                                    print(eap_attributes)
                                    NEXT_REAUTH_ID = self.get_eap_aka_attribute_value(eap_attributes,AT_NEXT_REAUTH_ID)

                                    if NEXT_REAUTH_ID is not None: 
                                        self.next_reauth_id = NEXT_REAUTH_ID.decode('utf-8')
                                        print('NEXT REAUTH ID',self.next_reauth_id)
                                    else:
                                        #should use permanent identity next 
                                        self.next_reauth_id = None


                                
                                return REPEAT_STATE,'NEW AKA_Challenge'


                        elif i[1][3] in (AKA_Notification,):
                            self.eap_identifier = i[1][1]
                            
                            NOTIFICATION = self.get_eap_aka_attribute_value(i[1][4],AT_NOTIFICATION)
                            
                            if NOTIFICATION < 32768: #error
                                print('EAP AT_NOTIFICATION with ERROR ' + str(NOTIFICATION))
                                self.eap_payload_response = bytes([2]) + bytes([self.eap_identifier]) + fromHex('0008170c0000') 
                                return REPEAT_STATE, 'General_Failure'
                     
                    elif i[1][0] in (EAP_FAILURE,):
                        return OTHER_ERROR,'EAP FAILURE'                     
                     
                     
                    else:
                        #check error
                        return MANDATORY_INFORMATION_MISSING,'NO RAND/AUTN IN EAP'

            if eap_received == True:
                return OK,''               
            else:
                return MANDATORY_INFORMATION_MISSING,'NO EAP PAYLOAD RECEIVED'
        


    def state_4(self):
        self.message_id_request += 1
        packet = self.create_IKE_AUTH_3()
        self.send_data(packet)
        print('sending IKE_AUTH (3)')        
            
        try:
            while True:
                if self.userplane_mode == ESP_PROTOCOL:
                    packet, address = self.socket.recvfrom(2000)  
                    self.decode_ike(packet)
                    if self.ike_decoded_ok == True: break                
                else:
                    packet, address = self.socket_nat.recvfrom(2000)  
                    self.decode_ike(packet[4:])
                    if self.ike_decoded_ok == True: break                     
                
        except: #timeout
            return TIMEOUT,'TIMEOUT'            
            
        if self.ike_decoded_header['exchange_type'] == IKE_AUTH and self.decoded_payload[0][0] == SK:
            print('received IKE_AUTH (3)')             
            for i in self.decoded_payload[0][1]:
                
                if i[0] == N:    #protocol_id, notify_message_type, spi, notification_data
                    ntype = i[1][1]
                    if ntype<16384: #error
                        self.log_notify_error(ntype, "IKE_AUTH")
                        return OTHER_ERROR,str(ntype)
                    elif ntype in (PDN_TYPE_IPv4_ONLY_ALLOWED, PDN_TYPE_IPv6_ONLY_ALLOWED):
                        # The network is telling us only one PDN type is allowed. We request an
                        # IPv6-only CFG for Telus already, so this is informational; log it.
                        swu_log("IKE_AUTH status: %s (%s)" % (notify_name(ntype), notify_describe(ntype)))
                    elif ntype == BACKOFF_TIMER:
                        secs, txt = (None, "?")
                        if i[1][3]:
                            secs, txt = self.decode_backoff_timer(i[1][3][-1])
                        swu_log("IKE_AUTH status: BACKOFF_TIMER = %s" % txt)

                elif i[0] == CP:
                    
                    if i[1][0] == CFG_REPLY:
                        self.ip_address_list = self.get_cp_attribute_value(i[1][1],INTERNAL_IP4_ADDRESS)
                        self.dns_address_list = self.get_cp_attribute_value(i[1][1],INTERNAL_IP4_DNS)
                        self.pcscf_address_list = self.get_cp_attribute_value(i[1][1],P_CSCF_IP4_ADDRESS)
                        self.ipv6_address_list = self.get_cp_attribute_value(i[1][1],INTERNAL_IP6_ADDRESS)
                        self.dnsv6_address_list = self.get_cp_attribute_value(i[1][1],INTERNAL_IP6_DNS) 
                        self.pcscfv6_address_list = self.get_cp_attribute_value(i[1][1],P_CSCF_IP6_ADDRESS)
                        print('IPV4 ADDRESS', self.ip_address_list)
                        print('DNS IPV4 ADDRESS', self.dns_address_list)
                        print('P-CSCF IPV4 ADDRESS', self.pcscf_address_list)
                        print('IPV6 ADDRESS', self.ipv6_address_list)
                        print('DNS IPV6 ADDRESS', self.dnsv6_address_list)                        
                        print('P-CSCF IPV6 ADDRESS', self.pcscfv6_address_list)
                        if self.ip_address_list == [] and self.ipv6_address_list == []:
                            return OTHER_ERROR,'NO IP ADDRESS (IPV4 or IPV6)'                       
                    else:
                        #check error
                        return OTHER_ERROR,'NO CP REPLY'                     
                        
                elif i[0] == SA:
                    proposal = i[1][0]
                    protocol_id = i[1][1]
                    self.spi_resp_child = i[1][2]
                    if protocol_id == ESP:
                        self.set_sa_negotiated_child(proposal)
                        print('IPSEC RESP SPI',toHex(self.spi_resp_child))
                        print('IPSEC INIT SPI',toHex(self.spi_init_child))
                    else:
                        return MANDATORY_INFORMATION_MISSING,'MANDATORY_INFORMATION_MISSING'

            self.generate_keying_material_child()
            return OK,''               


    def state_delete(self,initiator,kill = True):
        if initiator == True:
            
            #if kill == True: #reauth scenario without delete (comment this line, and uncomment the next one)
            if True:        
                self.message_id_request += 1
                packet = self.create_INFORMATIONAL_delete(IKE)
                self.send_data(packet)
                print('sending INFORMATIONAL (delete IKE)')
                
            self.ike_to_ipsec_encoder.send(bytes([INTER_PROCESS_DELETE_SA]))
            self.ike_to_ipsec_decoder.send(bytes([INTER_PROCESS_DELETE_SA])) 
            self.delete_routes()   
            if kill == True:
                exit(1)

        
        else:
            # Scan the request: is there a DELETE payload, and is REACTIVATION_REQUESTED_CAUSE
            # present? (TS 24.302 clause 7.2.4.2: a DELETE carrying REACTIVATION_REQUESTED_CAUSE
            # means the UE should re-establish the tunnel — our entrypoint supervisor does this
            # automatically on exit.)
            has_delete = any(i[0] == D for i in self.decoded_payload[0][1])
            reactivation = any(i[0] == N and i[1][1] == REACTIVATION_REQUESTED_CAUSE
                               for i in self.decoded_payload[0][1])
            if reactivation:
                swu_log("INFORMATIONAL: REACTIVATION_REQUESTED_CAUSE received - tunnel will be "
                        "re-established after release")

            if not has_delete:
                # Not a DELETE: DPD liveness check, DEVICE_IDENTITY request, or a status notify.
                # Answer it so the ePDG does not consider us dead. (Previously ignored -> the
                # ePDG's DPD would eventually tear the tunnel down.)
                self.handle_INFORMATIONAL_request()
                return

            for i in self.decoded_payload[0][1]:
                if i[0] == D: # delete

                    protocol = i[1][0]
                    num_spi = i[1][1]
                    spi_list = i[1][2]
                    if protocol == IKE:
                        print('received INFORMATIONAL (DELETE IKE)')
                        #delete everything, answer and quit
                        packet = self.answer_INFORMATIONAL_delete()
                        self.send_data(packet)
                        print('answering INFORMATIONAL (DELETE IKE)')
                        if self.old_ike_message_received == False:
                            self.ike_to_ipsec_encoder.send(bytes([INTER_PROCESS_DELETE_SA]))
                            self.ike_to_ipsec_decoder.send(bytes([INTER_PROCESS_DELETE_SA]))
                            self.delete_routes()
                            exit(1)

                    elif protocol == ESP:
                        print('received INFORMATIONAL (DELETE SA CHILD)')
                        packet = self.answer_INFORMATIONAL_delete_CHILD(ESP,self.spi_init_child_old)
                        self.send_data(packet)
                        print('answering INFORMATIONAL (DELETE SA CHILD)')
                        
                        
    def state_epdg_create_sa(self):
    
        isIKE = False
        isESP = False

        print('\nSTATE ePDG STARTED IKE/IPSEC REKEY:\n----------------------------------')     
                         
        print(self.decoded_payload)
        for i in self.decoded_payload[0][1]:
            if i[0] == SA: #
                proposal = i[1][0]
                protocol_id = i[1][1]
                spi = i[1][2]
                
                if protocol_id == IKE:
                    isIKE = True
   
                elif protocol_id == ESP:
                    isESP = True
                    
            elif i[0] == NINR:
                self.nounce_received = i[1][0]    

        if isIKE == True:
            print('received CREATE_CHILD_SA (IKE)')
            self.state_ue_create_sa(-1)
 
        if isESP == True:
            print('received CREATE_CHILD_SA (IPSEC)')
            packet = self.answer_NOTIFY_NO_PROPOSAL_CHOSEN()
            self.send_data(packet) 
            print('answering CREATE_CHILD_SA (IPSEC: NO PROPROSAL CHOSEN)')
            
            self.state_ue_create_sa_child() 


  


    def state_ue_create_sa(self,lowest = 0): #IKEv2 REKEY
        print('\nSTATE UE STARTED IKE REKEY:\n--------------------------')        
        self.sa_list_negotiated[0][0][1] = 8
        self.sa_list_create_child_sa = self.sa_list_negotiated
                
        self.dh_create_private_key_and_public_bytes(self.iana_diffie_hellman.get(self.negotiated_diffie_hellman_group))   
        self.dh_group_num = self.negotiated_diffie_hellman_group 
        
        self.message_id_request += 1
        packet = self.create_CREATE_CHILD_SA(lowest)
        #send request
        self.send_data(packet)
        print('sending CREATE_CHILD_SA (IKE)')

    def state_ue_create_sa_child(self,lowest = 0): #IPSEC REKEY
        print('\nSTATE UE STARTED IPSEC REKEY:\n--------------------------')        

        self.sa_list_create_child_sa_child = self.sa_list_negotiated_child
                
        
        self.message_id_request += 1
        packet = self.create_CREATE_CHILD_SA_CHILD(lowest)
        #send request
        self.send_data(packet)
        print('sending CREATE_CHILD_SA (IPSEC)')
                
    def state_epdg_create_sa_response(self):
        isIKE = False
        isESP = False
        
        for i in self.decoded_payload[0][1]:
            if i[0] == SA: #
                proposal = i[1][0]
                protocol_id = i[1][1]
                spi = i[1][2]
                
                if protocol_id == IKE:
                    isIKE = True
                elif protocol_id == ESP:
                    isESP = True               
                    
            elif i[0] == KE:
                dh_peer_group = i[1][0]
                dh_peer_public_key_bytes = i[1][1]                            
                self.dh_calculate_shared_key(dh_peer_public_key_bytes)          
            
            elif i[0] == NINR:
                self.nounce_received = i[1][0]    


        if isIKE == True:
            print('received CREATE_CHILD_SA response IKE')
            self.message_id_request += 1
            packet = self.create_INFORMATIONAL_delete(IKE)
            
            self.ike_spi_responder_old = self.ike_spi_responder 
            self.ike_spi_initiator_old = self.ike_spi_initiator 
            
            self.ike_spi_responder = spi
            self.ike_spi_initiator = self.sa_spi_list[0] #only one proposal was made
            
            print('NEW IKE SPI INITIATOR',toHex(self.ike_spi_initiator))
            print('NEW IKE SPI RESPONDER',toHex(self.ike_spi_responder))
            
            self.generate_new_ike_keying_material()
            self.message_id_request = -1
            
            #send request
            self.send_data(packet)
            print('sending INFORMATIONAL (DELETE IKE old)')

        if isESP == True:
            print('received CREATE_CHILD_SA response IPSEC')                
            self.message_id_request += 1    
            self.spi_init_child_old = self.spi_init_child
            self.spi_resp_child_old = self.spi_resp_child            
            packet = self.create_INFORMATIONAL_delete(ESP,self.spi_init_child_old)

            self.spi_init_child = self.sa_spi_list[0] #only one proposal was made
            self.spi_resp_child = spi

            print('NEW CHILD SPI INITIATOR ',toHex(self.spi_init_child))
            print('NEW CHILD SPI RESPONDER',toHex(self.spi_resp_child))
            
            self.generate_keying_material_child()
            inter_process_list_start_encoder = [
                INTER_PROCESS_UPDATE_SA,
                [
                    (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                    (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_EI),
                    (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                    (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AI),
                    (INTER_PROCESS_IE_SPI_RESP, self.spi_resp_child)         
                ]
            ]
            
            inter_process_list_start_decoder = [
                INTER_PROCESS_UPDATE_SA,
                [
                    (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                    (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_ER),
                    (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                    (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AR),
                    (INTER_PROCESS_IE_SPI_INIT, self.spi_init_child)         
                ]
            ]
                        
            self.ike_to_ipsec_encoder.send(self.encode_inter_process_protocol(inter_process_list_start_encoder))
            self.ike_to_ipsec_decoder.send(self.encode_inter_process_protocol(inter_process_list_start_decoder))            
            
            #send request
            self.send_data(packet)        
            print('sending INFORMATIONAL (DELETE IPSEC old)')            

    def state_connected(self):
        #set udp 4500 socket (self.socket_nat)
     
        self.set_routes()
    
        #set ipsec tunnel handlers
        self.ike_to_ipsec_encoder, self.ipsec_encoder_to_ike = multiprocessing.Pipe()
        self.ike_to_ipsec_decoder, self.ipsec_decoder_to_ike = multiprocessing.Pipe()
           
        ipsec_input_worker = multiprocessing.Process(target = self.encapsulate_ipsec, args=([self.ipsec_encoder_to_ike],))
        ipsec_input_worker.start()
        ipsec_output_worker = multiprocessing.Process(target = self.decapsulate_ipsec, args=([self.ipsec_decoder_to_ike],))
        ipsec_output_worker.start()
        
        inter_process_list_start_encoder = [
            INTER_PROCESS_CREATE_SA,
            [
                (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_EI),
                (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AI),
                (INTER_PROCESS_IE_SPI_RESP, self.spi_resp_child)         
            ]
        ]

        inter_process_list_start_decoder = [
            INTER_PROCESS_CREATE_SA,
            [
                (INTER_PROCESS_IE_ENCR_ALG, self.negotiated_encryption_algorithm_child),
                (INTER_PROCESS_IE_ENCR_KEY, self.SK_IPSEC_ER),
                (INTER_PROCESS_IE_INTEG_ALG, self.negotiated_integrity_algorithm_child),
                (INTER_PROCESS_IE_INTEG_KEY, self.SK_IPSEC_AR),
                (INTER_PROCESS_IE_SPI_INIT, self.spi_init_child)         
            ]
        ]
             
        self.ike_to_ipsec_encoder.send(self.encode_inter_process_protocol(inter_process_list_start_encoder))
        self.ike_to_ipsec_decoder.send(self.encode_inter_process_protocol(inter_process_list_start_decoder))

        # VoWiFi engine addition: tunnel is up. Publish P-CSCF + state and notify the manager
        # (replaces strongSwan's ims.updown + charon P-CSCF log parsing).
        pcscf = (self.pcscfv6_address_list[0] if getattr(self, "pcscfv6_address_list", [])
                 else (self.pcscf_address_list[0] if getattr(self, "pcscf_address_list", []) else ""))
        inner = (self.ipv6_address_list[0] if self.ipv6_address_list
                 else (self.ip_address_list[0] if self.ip_address_list else ""))
        swu_write_pcscf(pcscf)
        swu_write_status("CONNECTED", inner_ip=inner, pcscf=pcscf, iface=self.tun_device)
        swu_log("tunnel CONNECTED inner=%s pcscf=%s iface=%s" % (inner, pcscf, self.tun_device))
        swu_notify("tunnel_up")
        if pcscf:
            swu_notify("pcscf", pcscf)
            # Keep pjsip's P-CSCF (identify/resolve/register) in sync when the ePDG assigns a
            # different P-CSCF on reconnect/reauth. No-op on first bring-up (entrypoint seeds
            # pcscf.applied after its own initial render, before Asterisk starts).
            swu_apply_pcscf(pcscf)

        # Headless control channel replaces interactive stdin. Open a FIFO O_RDWR so select()
        # never sees EOF (a plain stdin/EOF would busy-spin). The manager/entrypoint can echo
        # q/i/c/r into it. Absent a FIFO we simply run without a control channel.
        ctl_f = None
        if not self.netns_name:  # netns probe mode keeps interactive stdin
            try:
                ctl_path = os.environ.get("SWU_CTL_FIFO", os.path.join(SWU_RUNDIR, "swu.ctl"))
                os.makedirs(SWU_RUNDIR, exist_ok=True)
                if not os.path.exists(ctl_path):
                    os.mkfifo(ctl_path)
                ctl_f = os.fdopen(os.open(ctl_path, os.O_RDWR), "r")
            except Exception as e:
                swu_log("control FIFO unavailable: %r" % e)
                ctl_f = None
        ctl_src = ctl_f if ctl_f is not None else sys.stdin
        socket_list = [ctl_src, self.socket, self.ike_to_ipsec_decoder]
        
        while True:
            
            read_sockets, write_sockets, error_sockets = select.select(socket_list, [], [])
            
            for sock in read_sockets:
     
                if sock == self.socket:

                        
                    packet, server_address = self.socket.recvfrom(2000)                    
                    if server_address[0] == self.server_address[0]: #check server IP address. source port could be different than 500 or 4500, if it's a request reponse must be sent to the same port
                                  
                        self.decode_ike(packet)    
                        if self.ike_decoded_ok == True:
                
                            if self.ike_decoded_header['exchange_type'] == INFORMATIONAL and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 0:
                                self.state_delete(False)
                               
                            elif self.ike_decoded_header['exchange_type'] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 0:
                                self.state_epdg_create_sa()
                            
                            elif self.ike_decoded_header['exchange_type'] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 1:
                                self.state_epdg_create_sa_response() 
                            
                            
                        
                        if self.old_ike_message_received == True:
                            self.old_ike_message_received = False                                
                            
                   
                                    

                elif sock == self.ike_to_ipsec_decoder:
                    pipe_packet = self.ike_to_ipsec_decoder.recv()                     
                    decode_list = self.decode_inter_process_protocol(pipe_packet)
                    if decode_list[0] == INTER_PROCESS_IKE:

                        packet = decode_list[1][0][1]
                        
                        #if received via pipe it was sent to port udp 4500 (exclude 4 initial bytes)
                        self.decode_ike(packet[4:]) 

                        if self.ike_decoded_ok == True:                           
                            
                            if self.ike_decoded_header['exchange_type'] == INFORMATIONAL and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 0:
                                self.state_delete(False)
                            
                            elif self.ike_decoded_header['exchange_type'] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 0:
                                self.state_epdg_create_sa()                        
                        
                            elif self.ike_decoded_header['exchange_type'] == CREATE_CHILD_SA and self.decoded_payload[0][0] == SK and self.ike_decoded_header['flags'][0] == 1:
                                self.state_epdg_create_sa_response()   
                        
                        if self.old_ike_message_received == True:
                            self.old_ike_message_received = False

                else:
                    msg = ctl_src.readline()
                    if msg == "":            # control channel closed -> ignore (daemon keeps running)
                        continue
                    msg = msg.strip() + "\n"
                    if msg == "q\n":  #quit
                        self.state_delete(True)
                    elif msg =="i\n": #rekey ike
                        self.state_ue_create_sa()
                    elif msg =="c\n": #rekey sa child
                        self.state_ue_create_sa_child()
                    elif msg =="r\n": # restart process
                        self.state_delete(True,False)
                        if self.next_reauth_id is not None:
                            self.set_identification(IDI,ID_RFC822_ADDR,self.next_reauth_id)
                        else:
                            self.set_identification(IDI,ID_RFC822_ADDR,'0' + self.imsi + '@nai.epc.mnc' + self.mnc + '.mcc' + self.mcc + '.3gppnetwork.org')

                        self.iterations = 2
                        return

                    else:
                        pass


                        
    

    def start_ike(self):
        self.iterations = 2
        self.cookie = False
        while self.iterations>0:
        
            self.iterations -= 1
        
            print('\nSTATE 1:\n-------')
            result,info = self.state_1()
            if result in (REPEAT_STATE, TIMEOUT): 
                print(self.errors.get(result),':',info)
                print('\nSTATE 1 (retry 1):\n------- -------')
                result,info = self.state_1(retry=True)
            elif result in (REPEAT_STATE_COOKIE,):
                print(self.errors.get(result),':',info)
                print('\nSTATE 1 (retry 1 with cookie):\n------- -------')            
                result,info = self.state_1(retry=True, cookie=True)
                                
            if result in (REPEAT_STATE, TIMEOUT): 
                print(self.errors.get(result),':',info)
                print('\nSTATE 1: (retry 2)\n------- -------')
                if self.cookie == True:
                    result,info = self.state_1(retry=True, cookie=True)                
                else:
                    result,info = self.state_1(retry=True)
                                        
            if result == OK:
                print('\nSTATE 2:\n-------')
                result,info = self.state_2()
            else:
                print(self.errors.get(result),':',info)
                continue                
            
            if result in (REPEAT_STATE, OK):
                if result in (REPEAT_STATE,):
                    print(self.errors.get(result),':',info)
                    print('\nSTATE 2 (repeat):\n---------------')
                    result,info = self.state_2(retry=True)                      
                if result in (OK,):
                    print('\nSTATE 3:\n-------')
                    result,info = self.state_3()
            else:
                print(self.errors.get(result),':',info)
                continue 
                
            if result in (OK, REPEAT_STATE):
                if result in (REPEAT_STATE,):
                    print(self.errors.get(result),':',info)
                    print('\nSTATE 3 (repeat):\n---------------')
                    result,info = self.state_3()                                    
                if result in (OK,):
                    print('\nSTATE 4:\n-------')
                    result,info = self.state_4()                   
            else:
                print(self.errors.get(result),':',info)
                continue 
                
            if result == OK:
                print('\nSTATE CONNECTED. Press q to quit, i to rekey ike, c to rekey child sa, r to reauth.\n')
                self.state_connected()        
            else:
                print(self.errors.get(result),':',info)
                continue 
            
        exit(1)    
           
        

#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################
#######################################################################################################################

def get_default_gateway_linux():
    """Read the default gateway directly from /proc."""
    with open("/proc/net/route") as fh:
        for line in fh:
            fields = line.strip().split()
            if fields[1] != '00000000' or not int(fields[3], 16) & 2:
                continue
           
            return socket.inet_ntoa(struct.pack("<L", int(fields[2], 16))), fields[0]

def get_default_source_address():

    proc = subprocess.Popen("/sbin/ifconfig | grep -A 1 " + get_default_gateway_linux()[1] + " | grep inet", stdout=subprocess.PIPE, shell=True)
    output = str(proc.stdout.read())
    if 'addr:' in output:
        addr = output.split('addr:')[1].split()[0]
    else:
        addr = output.split('inet ')[1].split()[0]
    return addr

def toHex(value): # bytes hex string
    return hexlify(value).decode('utf-8')

def fromHex(value): # hex string to bytes
    return unhexlify(value)
    

def sha1_dss(data):  #for MSK
#based on code from https://codereview.stackexchange.com/questions/37648/python-implementation-of-sha1    

    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    def rol(n, b):
        return ((n << b) | (n >> (32 - b))) & 0xffffffff

    #special padding. data always 160 bits (20 bytes, so 44 bytes left to 64Bytes block)
    padding = 44*b'\x00'
    padded_data = data + padding 
    
    thunks = [padded_data[i:i+64] for i in range(0, len(padded_data), 64)]
    for thunk in thunks:
        w = list(struct.unpack('>16L', thunk)) + [0] * 64
        for i in range(16, 80):
            w[i] = rol((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1)

        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(0, 80):
            if 0 <= i < 20:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i < 40:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i < 60:
                f = (b & c) | (b & d) | (c & d) 
                k = 0x8F1BBCDC
            elif 60 <= i < 80:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            a, b, c, d, e = rol(a, 5) + f + e + k + w[i] & 0xffffffff, \
                            a, rol(b, 30), c, d

        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff

    #return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)
    return struct.pack('!I',h0) + struct.pack('!I',h1) + struct.pack('!I',h2) + struct.pack('!I',h3) + struct.pack('!I',h4)


#abstraction functions

def milenage_res_ck_ik(ki, op, opc, rand):
    rand = unhexlify(rand)
    ki = unhexlify(ki)
    if op == None: 
        opc = unhexlify(opc)
        op = 16*b'\x00' #dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        op = unhexlify(op)
        m = Milenage(op)
    res, ck, ik, ak = m.f2345(ki, rand)
    return hexlify(res), hexlify(ck), hexlify(ik)


def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def return_auts(rand, autn,ki,op,opc,sqn):
    rand = unhexlify(rand)
    ki = unhexlify(ki)
    autn = unhexlify(autn)
    sqn = unhexlify(sqn)
    if op == None: 
        opc = unhexlify(opc)
        op = 16*b'\x00' #dummy since we will set opc directly
        m = Milenage(op)
        m.set_opc(opc)
    else:
        op = unhexlify(op)
        m = Milenage(op)
    macs = m.f1star(ki,rand,sqn,b'\x00\x00')
    ak = m.f5star(ki,rand)
    ak_xor_sqn = byte_xor(ak, sqn)
    return  ak_xor_sqn + macs


def return_imsi(serial_interface_or_reader_index):
    try:
        return read_imsi_2(serial_interface_or_reader_index)
    except:
        try:
            return get_imsi(serial_interface_or_reader_index)
        except:
            try:
                return https_imsi(serial_interface_or_reader_index)
            except:
                print('Unable to access serial port/smartcard reader/server. Using DEFAULT IMSI: ' + DEFAULT_IMSI)
                return DEFAULT_IMSI
        
def return_res_ck_ik(serial_interface_or_reader_index, rand, autn, ki, op, opc):
    if ki is not None and (op is not None or opc is not None):
        try:
            return milenage_res_ck_ik(ki, op, opc, rand)
        except:
            print('Unable to calculate Milenage RES/CK/IK. Check KI, OP or OPC. Using DEFAULT RES, CK and IK')
            return DEFAULT_RES, DEFAULT_CK, DEFAULT_IK
    else:
        try:
            return read_res_ck_ik_2(serial_interface_or_reader_index, rand, autn)
        except:
            try:        
                return get_res_ck_ik(serial_interface_or_reader_index, rand, autn)
            except:
                try:
                    return https_res_ck_ik(serial_interface_or_reader_index, rand, autn)
                except:
                    print('Unable to access serial port/smartcard reader/server. Using DEFAULT RES, CK and IK')
                    return DEFAULT_RES, DEFAULT_CK, DEFAULT_IK




def get_imsi(serial_interface):

    imsi = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
    CLI.append('AT+CIMI\r\n')
    
    a = time.time()
    for i in range(len(CLI)):
        ser.write(CLI[i].encode())
        buffer = ''

        while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
            buffer +=  ser.read().decode("utf-8")
            
            if time.time()-a > 0.5:
                ser.write(CLI[i].encode())
                a = time.time() +1
            
        if i==0:    
            for m in buffer.split('\r\n'):
                if len(m) == 15:
                    imsi = m
         
    ser.close()
    return imsi


def get_res_ck_ik(serial_interface, rand, autn):
    res = None
    ck = None
    ik = None
    
    ser = serial.Serial(serial_interface,38400, timeout=0.5,xonxoff=True, rtscts=True, dsrdtr=True, exclusive =True)

    CLI = []
   
    #CLI.append('AT+CRSM=178,12032,1,4,0\r\n')
    CLI.append('AT+CSIM=14,"00A40000023F00"\r\n')
    CLI.append('AT+CSIM=14,"00A40000022F00"\r\n')
    CLI.append('AT+CSIM=42,"00A4040010A0000000871002FFFFFFFF8903050001"\r\n')
    CLI.append('AT+CSIM=78,\"008800812210' + rand.upper() + '10' + autn.upper() + '\"\r\n')

    a = time.time()
    for i in CLI:
        ser.write(i.encode())
        buffer = ''
    
        while "OK" not in buffer and "ERROR" not in buffer:
            buffer +=  ser.read().decode("utf-8")
        
            if time.time()-a > 0.5:
                ser.write(i.encode())

                a = time.time() + 1
                
    for i in buffer.split('"'):
        if len(i)==4:
            if i[0:2] == '61':
                len_result = i[-2:]
    
    LAST_CLI = 'AT+CSIM=10,"00C00000' + len_result + '\"\r\n'
    ser.write(LAST_CLI.encode())
    buffer = ''
    
    while "OK\r\n" not in buffer and "ERROR\r\n" not in buffer:
        buffer +=  ser.read().decode("utf-8")
        
    for result in buffer.split('"'):
        if len(result) > 10:
        

            res = result[4:20]
            ck = result[22:54]
            ik = result[56:88]
    
    ser.close()    
    return res, ck, ik
    

#reader functions
def bcd(chars):
    bcd_string = ""
    for i in range(len(chars) // 2):
        bcd_string += chars[1+2*i] + chars[2*i]
    return bcd_string

def read_imsi(reader_index):
    imsi = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))     
    data, sw1, sw2 = connection.transmit(toBytes('00A40000027F20'))
    data, sw1, sw2 = connection.transmit(toBytes('00A40000026F07'))
    data, sw1, sw2 = connection.transmit(toBytes('00B0000009'))  
    result = toHexString(data).replace(" ","")
    imsi = bcd(result)[-15:]
    
    return imsi

def read_res_ck_ik(reader_index, rand, autn):
    res = None
    ck = None
    ik = None
    r = readers()
    connection = r[int(reader_index)].createConnection()
    connection.connect()
    data, sw1, sw2 = connection.transmit(toBytes('00A40000023F00'))    
    data, sw1, sw2 = connection.transmit(toBytes('00A40000022F00')) 
    data, sw1, sw2 = connection.transmit(toBytes('00A4040010A0000000871002FFFFFFFF8903050001'))   
    data, sw1, sw2 = connection.transmit(toBytes('008800812210' + rand.upper() + '10' + autn.upper()))   
    if sw1 == 97:
        data, sw1, sw2 = connection.transmit(toBytes('00C00000') + [sw2])         
        result = toHexString(data).replace(" ", "")
        res = result[4:20]
        ck = result[22:54]
        ik = result[56:88]          

    return res, ck, ik

#reader functions - more generic using card module
def read_imsi_2(reader_index): #prepared for AUTS
    a = USIM(int(reader_index))
    print(a.get_imsi())
    return a.get_imsi()
    
def read_res_ck_ik_2(reader_index,rand,autn):
    # PIN handling (VoWiFi engine addition): if USIM_PIN is set, we MUST VERIFY CHV1 before
    # AUTHENTICATE or PIN-enabled cards (e.g. Telus) return 0x6982. VERIFY + AUTHENTICATE must
    # happen in the SAME PC/SC connection (CHV1 does not reliably persist across a fresh
    # connection when strongSwan-style resets occur). When no PIN is configured we fall through
    # to the UPSTREAM path (mitshell card.USIM) unchanged, so PIN-less / 3rd-party cards behave
    # exactly as the original emulator -- same gating as the strongSwan 03 patch.
    pin = os.environ.get("USIM_PIN", "").strip()
    if pin and pin.lower() not in ("none", "disabled"):
        return _read_res_ck_ik_pin(reader_index, rand, autn, pin)

    a = USIM(int(reader_index))
    x = a.authenticate(RAND=toBytes(rand), AUTN=toBytes(autn))
    if len(x) == 1: #AUTS goes in RES position
        return toHexString(x[0]).replace(" ", ""), None, None
    elif len(x) > 2:
        return toHexString(x[0]).replace(" ", ""),toHexString(x[1]).replace(" ", ""),toHexString(x[2]).replace(" ", "")
    else:
        return None, None, None


# --- USIM AKA with CHV1 verify, single connection (VoWiFi engine addition) ------------------
# Mirrors engine/pin_keeper.py: SELECT MF -> EF.DIR (scan for the 3GPP USIM AID, robust across
# vendors that list CSIM first) -> ADF.USIM -> [VERIFY CHV1] -> AUTHENTICATE(AKA). Returns the
# same (res, ck, ik) / (auts, None, None) convention the caller expects.
_USIM_AID_PREFIX = "A0000000871002"


def _swu_select_adf_usim(conn):
    conn.transmit(toBytes("00a40004023f0000"))               # SELECT MF
    d, s1, s2 = conn.transmit(toBytes("00a40004022f0000"))   # SELECT EF.DIR
    if s1 != 0x61:
        return False
    fcp, s1, s2 = conn.transmit(toBytes("00C00000") + [s2])
    if s1 != 0x90 or len(fcp) < 8:
        return False
    rec_len = fcp[7]
    aid = None
    first = None
    for rec in range(1, 11):
        d, s1, s2 = conn.transmit(toBytes("00b2") + [rec, 0x04, rec_len])
        if s1 != 0x90 or len(d) < 5 or d[0] != 0x61 or d[2] != 0x4F:
            break
        aid_len = d[3]
        a = "".join("%02X" % b for b in d[4:4 + aid_len])
        if len(a) < aid_len * 2:
            break
        if a.startswith(_USIM_AID_PREFIX):
            aid = (aid_len, a)
            break
        if first is None:
            first = (aid_len, a)
    if aid is None:
        aid = first
    if aid is None:
        return False
    aid_len, a = aid
    d, s1, s2 = conn.transmit(toBytes("00a40404") + [aid_len] + toBytes(a))
    return s1 == 0x61


def _swu_verify_chv1(conn, pin):
    """Non-consuming tries probe, then VERIFY if needed. PUK-safe (never spend below 2 tries)."""
    d, s1, s2 = conn.transmit(toBytes("0020000100"))         # VERIFY, empty body
    if (s1, s2) == (0x90, 0x00):
        return True                                          # already verified this session
    if s1 == 0x63:
        if (s2 & 0x0F) < 2:
            print("VoWiFi: refusing PIN VERIFY, only %d tries left (PUK-safe)" % (s2 & 0x0F))
            return False
    elif (s1, s2) == (0x69, 0x83):
        print("VoWiFi: CHV1 blocked")
        return False
    body = [ord(c) for c in pin] + [0xFF] * (8 - len(pin))
    d, s1, s2 = conn.transmit(toBytes("00200001") + [0x08] + body)
    ok = (s1, s2) == (0x90, 0x00)
    print("VoWiFi: VERIFY CHV1 %s before AUTHENTICATE" % ("ok" if ok else "FAILED sw=%02x%02x" % (s1, s2)))
    return ok


def _pcsc_hcard(conn):
    obj = conn
    for _ in range(5):
        if hasattr(obj, "hcard"):
            return obj.hcard
        if hasattr(obj, "component") and obj.component is not None:
            obj = obj.component
            continue
        break
    return None


def _read_res_ck_ik_pin(reader_index, rand, autn, pin):
    r = readers()
    conn = r[int(reader_index)].createConnection()
    conn.connect()
    # Exclusive PC/SC transaction for the whole SELECT->VERIFY->AUTHENTICATE sequence: pcscd
    # serializes single APDUs but NOT multi-APDU groups, so without this ami_usim's own AKA
    # APDUs could interleave during a reauth and corrupt the sequence.
    hcard = _pcsc_hcard(conn) if SCardBeginTransaction else None
    if hcard is not None:
        try:
            SCardBeginTransaction(hcard)
        except Exception:
            hcard = None
    try:
        if not _swu_select_adf_usim(conn):
            print("VoWiFi: ADF.USIM select failed")
            return None, None, None
        _swu_verify_chv1(conn, pin)
        # AUTHENTICATE (AKA security context): 00 88 00 81 22 10 <RAND> 10 <AUTN>
        apdu = "00880081" + "22" + "10" + rand.upper() + "10" + autn.upper()
        d, s1, s2 = conn.transmit(toBytes(apdu))
        if s1 == 0x61:
            d, s1, s2 = conn.transmit(toBytes("00C00000") + [s2])
        if (s1, s2) != (0x90, 0x00):
            print("VoWiFi: AUTHENTICATE failed sw=%02x%02x" % (s1, s2))
            return None, None, None
        result = toHexString(d).replace(" ", "")
        if not result:
            return None, None, None
        tag = result[0:2].lower()
        if tag == "db":            # success: 'db' <res_len> RES <ck_len> CK <ik_len> IK
            p = 2
            rl = int(result[p:p + 2], 16); p += 2
            res = result[p:p + rl * 2]; p += rl * 2
            cl = int(result[p:p + 2], 16); p += 2
            ck = result[p:p + cl * 2]; p += cl * 2
            il = int(result[p:p + 2], 16); p += 2
            ik = result[p:p + il * 2]
            return res, ck, ik
        if tag == "dc":            # sync failure: 'dc' <auts_len> AUTS  (CK=None signals AUTS)
            al = int(result[2:4], 16)
            return result[4:4 + al * 2], None, None
        return None, None, None
    finally:
        if hcard is not None:
            try:
                SCardEndTransaction(hcard, SCARD_LEAVE_CARD)
            except Exception:
                pass
        try:
            conn.disconnect()
        except Exception:
            pass


#https functions
def https_imsi(server):
    r = requests.get('https://' + server + '/?type=imsi', verify=False)
    return r.json()['imsi']

def https_res_ck_ik(server, rand, autn):
    r = requests.get('https://' + server + '/?type=rand-autn&rand=' + rand + '&autn=' + autn, verify=False)
    return r.json()['res'], r.json()['ck'], r.json()['ik']





#################################################################################################################    
#####
#####   SA Structure:
#####   ------------
#####
#####   sa_list = [ (proposal 1), (proposal 2), ... , (proposal n)   ]
#####
#####   proposal = (Protocol ID, SPI Size) , (Transform 1), (transform 2), ... , (transform n)
#####
#####   transform = Tranform Type, Transform ID, (Transform Attributes)
#####
#####   transform attribute = Attribute type, value
#####
#################################################################################################################


#################################################################################################################    
#####
#####   TS Structure:
#####   ------------
#####
#####   ts_list = [ (ts 1), (ts 2), ... , (ts n)   ]
#####
#####   ts = ts_type, ip_protocol_id, start_port, end_port, starting_address, ending_address
#####
#################################################################################################################


#################################################################################################################    
#####
#####   CP Structure:
#####   ------------
#####
#####   cp_list = [ cfg_type, (attribute 1), ... , (attribute n)   ]
#####
#####   attribute = attribute type, value1, value2, .... (depends on the attribute type)
#####
#################################################################################################################



def main():

    # CFG request. Telus assigns an IPv6-only VoWiFi PDN and only returns P_CSCF_IP6_ADDRESS
    # when the request is IPv6-only (matching a real UE / strongSwan-epdg). When we also asked
    # for the IPv4 attributes, Telus returned the inner IPv6 address but NO P-CSCF at all, which
    # left Asterisk with no IMS proxy. Requesting exactly what strongSwan requests
    # (INTERNAL_IP6_ADDRESS, INTERNAL_IP6_DNS, P_CSCF_IP6_ADDRESS) makes Telus return the P-CSCF.
    cp_list = [
        CFG_REQUEST,
        [INTERNAL_IP6_ADDRESS],
        [INTERNAL_IP6_DNS],
        [P_CSCF_IP6_ADDRESS]
    ]

    ts_list_initiator = [
        [TS_IPV4_ADDR_RANGE,ANY,0,65535,'0.0.0.0','255.255.255.255'],
        [TS_IPV6_ADDR_RANGE,ANY,0,65535,'::','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']
    ]

    ts_list_responder = [
        [TS_IPV4_ADDR_RANGE,ANY,0,65535,'0.0.0.0','255.255.255.255'],
        [TS_IPV6_ADDR_RANGE,ANY,0,65535,'::','ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff']        
    ]


    # IKE proposals. Telus' ePDG rejects the emulator's stock SHA1/MD5 list with
    # NO_PROPOSAL_CHOSEN; it requires PRF/INTEG SHA2-256. This list mirrors the engine's
    # render.py default_ike (the set proven with strongSwan on Telus). MODP_2048 MUST be first
    # because the IKE_SA_INIT KE payload is derived from the first proposal's DH group.
    sa_list = [
    [
       [IKE,0],
       [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
       [PRF,PRF_HMAC_SHA2_256],
       [INTEG,AUTH_HMAC_SHA2_256_128],
       [D_H,MODP_2048_bit]
    ]    ,
    [
       [IKE,0],
       [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
       [PRF,PRF_HMAC_SHA2_256],
       [INTEG,AUTH_HMAC_SHA2_256_128],
       [D_H,MODP_2048_bit]
    ]    ,
    [
       [IKE,0],
       [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
       [PRF,PRF_HMAC_SHA1],
       [INTEG,AUTH_HMAC_SHA1_96],
       [D_H,MODP_2048_bit]
    ]    ,
    [
       [IKE,0],
       [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
       [PRF,PRF_HMAC_SHA1],
       [INTEG,AUTH_HMAC_SHA1_96],
       [D_H,MODP_2048_bit]
    ]
    ]


    # Child/ESP proposals. AES_CBC_128/HMAC_SHA1_96 first — the transform Telus selected with
    # strongSwan (render.py default_esp). Remaining kept as fallbacks. No DH transform here
    # (no PFS at initial IKE_AUTH).
    sa_list_child = [
    [
        [ESP,4],
        [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
        [INTEG,AUTH_HMAC_SHA1_96],
        [ESN,ESN_NO_ESN]
    ] ,
    [
        [ESP,4],
        [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
        [INTEG,AUTH_HMAC_SHA2_256_128],
        [ESN,ESN_NO_ESN]
    ] ,
    [
        [ESP,4],
        [ENCR,ENCR_AES_CBC,[KEY_LENGTH,128]],
        [INTEG,AUTH_HMAC_SHA2_256_128],
        [ESN,ESN_NO_ESN]
    ] ,
    [
        [ESP,4],
        [ENCR,ENCR_AES_CBC,[KEY_LENGTH,256]],
        [INTEG,AUTH_HMAC_SHA1_96],
        [ESN,ESN_NO_ESN]
    ]
    ]


    parser = OptionParser()    
    parser.add_option("-m", "--modem", dest="modem", default=DEFAULT_COM, help="modem port (i.e. COMX, or /dev/ttyUSBX), smartcard reader index (0, 1, 2, ...), or server for https")
    parser.add_option("-s", "--source", dest="source_addr",default=get_default_source_address(),help="IP address of source interface used for IKE/IPSEC")
    parser.add_option("-d", "--dest", dest="destination_addr",default=DEFAULT_SERVER,help="ip address or fqdn of ePDG") 
    parser.add_option("-a", "--apn", dest="apn", default=DEFAULT_APN, help="APN to use")    
    parser.add_option("-g", "--gateway_ip_address", dest="gateway_ip_address", help="gateway IP address")    
    parser.add_option("-I", "--imsi", dest="imsi",default=DEFAULT_IMSI,help="IMSI") 
    parser.add_option("-M", "--mcc", dest="mcc",default=DEFAULT_MCC,help="MCC of ePDG (3 digits)") 
    parser.add_option("-N", "--mnc", dest="mnc",default=DEFAULT_MNC,help="MNC of ePDG (3 digits)")   

    parser.add_option("-K", "--ki", dest="ki", help="ki for Milenage (if not using option -m)")    
    parser.add_option("-P", "--op", dest="op", help="op for Milenage (if not using option -m)")    
    parser.add_option("-C", "--opc", dest="opc", help="opc for Milenage (if not using option -m)") 
    parser.add_option("-n", "--netns", dest="netns", help="Name of network namespace for tun device")
    parser.add_option("-S", "--sqn", dest="sqn", help="SQN (6 hex bytes)")
    parser.add_option("-E", "--imei", dest="imei", default="",
                      help="IMEI (15 digits) for the ePDG DEVICE_IDENTITY response")
    parser.add_option("-V", "--imeisv", dest="imeisv", default="",
                      help="IMEISV (16 digits) for DEVICE_IDENTITY; auto-derived from IMEI if blank")

    (options, args) = parser.parse_args()
    
    try:
        destination_addr = socket.gethostbyname(options.destination_addr)
    except:
        print('Unable to resolve ' + options.destination_addr + '. Exiting.')
        exit(1)

    a = swu(options.source_addr,destination_addr,options.apn,options.modem,options.gateway_ip_address,options.mcc,options.mnc,options.imsi,options.ki,options.op,options.opc,options.netns, options.sqn)

    if options.imsi == DEFAULT_IMSI: a.get_identity()
    a.set_sa_list(sa_list)
    a.set_sa_list_child(sa_list_child)
    a.set_ts_list(TSI, ts_list_initiator)
    a.set_ts_list(TSR, ts_list_responder)
    a.set_cp_list(cp_list)
    a.set_device_identity(options.imei, options.imeisv)

    # VoWiFi engine addition: clean shutdown. On SIGTERM/SIGINT send an IKE DELETE so the ePDG
    # frees the SA immediately -- a hard kill leaves a lingering SA that makes the NEXT
    # IKE_SA_INIT get NO_PROPOSAL_CHOSEN until the ePDG's liveness timer expires.
    def _term(signum, frame):
        swu_log("signal %d -> tearing down tunnel (IKE DELETE)" % signum)
        try:
            swu_write_status("DOWN")
            swu_notify("tunnel_down")
        except Exception:
            pass
        try:
            a.state_delete(True)     # sends INFORMATIONAL(DELETE IKE), removes routes, exit(1)
        except SystemExit:
            raise
        except Exception:
            os._exit(0)
    _signal.signal(_signal.SIGTERM, _term)
    _signal.signal(_signal.SIGINT, _term)

    swu_write_status("CONNECTING")
    try:
        a.start_ike()
    finally:
        # start_ike only returns/raises when the tunnel could not be (re)established.
        swu_write_status("DOWN")
        swu_notify("tunnel_down")
    
    
    
if __name__ == "__main__":
    main()
    
