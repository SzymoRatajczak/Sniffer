import socket
import struct
import textwrap


#Ethernet Frame is used in communcation with router
#it is made od reciver/sender address,protocol and payload(data)
#first of all we are creating socket from where data will be taken
#follow by this data must be converted into human friendly format
def main():
    conn=socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.htons(3))
    while True:
        row_data,addr=conn.recvfrom(65536)
        dest_adr,src_adr,carring_protocol,data=Ethernet_Frame(row_data)
        print('\n Ethernet Frame')
        print('Destination{},Source{},Protocol{}'.format(dest_adr,src_adr,carring_protocol))

        if carring_protocol==8:
            version,header_length,ttl,proto,src,target,data=ipv4_unpack(data)
            print("IPv4 Packet")
            print("Version{},Header_Length{},TTL{},".format(version,header_length,ttl))
            print("Protocol{},Source{},Target{},".format(proto, src,target))

            if proto==1:
                icmp_type, code, check_sum=ICMP_packet(data)
                print('ICMP Packet')
                print('Type{},Code{},CheckSum{}'.format(icmp_type,code,check_sum))
                print(Mutli_line('\t\t\t\t',data))
            elif proto==6:
                source_port, destination_port, sequence, acknowledgemnts, offset, flag_ack, flag_fin, flag_psh, flag_rst, flag_syn, flag_urg=TCP_packet(data)
                print("TCP segment")
                print('Source{},Destination{}'.fomrat(source_port,destination_port))
                print('Sequence{},Acknowledgemnts{}'.format(sequence,acknowledgemnts))
                print('offset{}'.format(offset))
                print('ACK{},FIN{},PSH{},RST{},SYN{},URG{}'.format(flag_ack,flag_fin,flag_psh,flag_syn,flag_urg))
                print(Mutli_line('\t\t\t\t',data))
            elif proto==17:
                src_address, dest_address, size =UDP_unpack(data)
                print('UDP Packet')
                print('Source{},Destination{},Size{}'.format(src_address,dest_address,size))
            else:
                print(Mutli_line('\t\t',data))
        else:
            print(Mutli_line('\t\t',data))



#here we are taking informations from ethernet frame which will be passing to
#converting function
def Ethernet_Frame(data):
    dest_addr,src_addr,carring_protocol,data=struct.unpack('! 6s 6s H',data[:14])
    return  get_Mac(dest_addr),get_Mac(src_addr),socket.ntohs(carring_protocol),data[:14]


#make human friendly format
def get_Mac(data):
    response=map('{:02x}'.format,data)
    return  ':'.join(response).upper()


#Up to this point we were handling Ethernet frame-communctaion with router
#from now we are handling communciation via IP- communication with e.g server which is put somwhere in the internet and so on so forth
#if entire IP packet is too big , it will be divided into smaller packets and reunited at the end station
def ipv4_unpack(data):
    version=data[0]#data[0] consists of version and header length  so i shift this one with 4 bits to dissect merely version

    only_version=(version)>>4 #now i have only version and header length was shifted
    #to get header length( what is important beceause  after this we have out payload-data)
    #i must multiple by 4 bits

    header_length=(version & 15)*4
    #header length provides with information how long is the IP Header and in this IP Header
    #I can get info like ttl,src,dest,protocol (this ones can be found within  header_length)
    #After IP Header , payload can be found
    ttl,protocol,src,dest=struct.unpack('! 8x B B 2x 4s 4s',data[:header_length])
    return  only_version,header_length,ttl,ipv4_format(src),ipv4_format(dest),data[header_length:]


def ipv4_format(adr):
    return  ':'.join(map(str,adr)).upper()


def ICMP_packet(data):
    icmp_type,code,check_sum=struct.unpack('! B B H',data[:4])
    return  icmp_type,code,check_sum,data[4:]


def TCP_packet(data):
    source_port,destination_port,sequence,acknowledgemnts,offset_reserved_flags=struct.unpack('! H H L L H',data[:4])
    offset=(offset_reserved_flags>>12)*4 #in order to dissect offset
    flag_urg=(offset_reserved_flags&32)>>5
    flag_ack=(offset_reserved_flags&16)>>4
    flag_psh=(offset_reserved_flags&8)>>3
    flag_rst=(offset_reserved_flags&4)>>2
    flag_syn=(offset_reserved_flags&2)>>1
    flag_fin=offset_reserved_flags &1
    return  source_port,destination_port,sequence,acknowledgemnts,offset,flag_ack,flag_fin,flag_psh,flag_rst,flag_syn,flag_urg,data[offset:]


def UDP_unpack(data):
    src_address,dest_address,size=struct.unpack('!H H 2x H',data[:8])
    return  src_address,dest_address,size


#format multiline data
def Mutli_line(prefix,string,size=80):
    size=len(prefix)
    if isinstance(string,bytes):
        string=''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size %2:
            size-=1
    return  '\n'.join([prefix +line for line in textwrap.wrap(string,size)])

main()
