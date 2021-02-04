from scapy.all import *

ISAKMP_KEX_NAME = "ISAKMP Key Exchange"
ISAKMP_NONCE_NAME = "ISAKMP Nonce"

def getIniatorSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    return packets[0]["ISAKMP"]

def getResponderSAPacket(packets: []) -> scapy.layers.isakmp.ISAKMP:
    return packets[1]["ISAKMP"]

def getPayloadFromISAKMP(packet: scapy.layers.isakmp.ISAKMP, name: str) -> bytes:
    # name == payload name
    # TODO Get the corresponding load from the selected (by name) layer
    return packet[name].fields['load']

def getCookieFromISAKMP(respPacket: scapy.layers.isakmp.ISAKMP, responderCookie: bool) -> bytes:
    # TODO return corresponding cookie value
    # true -> responder cookie
    # false -> initiator cookie
    if (responderCookie):
        return respPacket.fields['resp_cookie']
    else:
        return respPacket.fields["init_cookie"]

def getSAPayloadFromInitPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Get the SA payload only from initiator packet
    SaPacket = packet[1] # SA -> 2nd part of the packets
    ByteChange = bytes(SaPacket)
    ByteSize = SaPacket.length
    return ByteChange[4:ByteSize] # DOI starts 4th  

def getResponderIDFromRespPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Return responder ID from ISAKMP layer 
    # Responder ID consist of  IDType||ProtoID||Port||load
    byteIdType = bytes([packet["ISAKMP Identification"].fields["IDtype"]])
    byteProtoID = bytes([packet["ISAKMP Identification"].fields["ProtoID"]])
    bytePort = packet["ISAKMP Identification"].fields["Port"].to_bytes(2, byteorder='little')
    consist =b"".join([byteIdType, byteProtoID, bytePort, packet["ISAKMP Identification"].fields["load"]])
    return consist

def getRespHashfromPacket(packet: scapy.layers.isakmp.ISAKMP) -> bytes:
    # TODO Get the hash value to compare your computed value against
    return packet["ISAKMP Hash"].fields['load']
