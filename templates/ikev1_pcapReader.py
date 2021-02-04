from scapy.all import *
def openPCAPFile(path: str) -> scapy.plist.PacketList:
    #TODO Read a pcap or pcapng file and return a packet list
    try:
        return rdpcap(path)
    except:
        raise Exception("File is not found")
    raise NotImplementedError('Reading packets not implemented.')

def getISAKMPPackets(packets: scapy.plist.PacketList) -> []:
    #TODO returns a list containing only the ISAKMP Layers of the packets in packetList 
    packetList = []
    for packet in packets:
        try:
            packetList.append(packet["ISAKMP"])
        except:
            continue
    return packetList    
    raise NotImplementedError('Getting ISAKMP Layer from PacketList not implemented.')
