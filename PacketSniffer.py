# Made by FoxSinOfGreed
# Many thanks to Zaid Sabih and Udemy.com

import scapy.all as scapy
from scapy.layers import http
from scapy.layers import inet
import subprocess

verb = 1


def sniffer(interface):
    scapy.sniff(iface=interface, store=False, prn=analysis)
    # iface stands for the interface we'd like to listen
    # store=False tells program not to store packet info in memory so that it doesn't put too much load
    # prn allows us to call a callback function
    # i.e. it will call a function each time it intercepts a packet
    # if we want to put a filter, theres another field - filters=''


def analysis(packet):
    # here we're checking for a http packet
    if packet.haslayer(http.HTTPRequest):
        # printing URL first
        if verb == 1:
            pass
        elif verb == 2:
            print(packet.summary())
        elif verb == 3:
            verbose_3(packet)
        elif verb == 4:
            verbose_4(packet)
        elif verb == 5:
            print(packet.show())
        url = get_url(packet)
        print("[+] Extracting URL ")
        print(url)
        # print(packet.show())
        # print(packet.summary())
        # from this, we come to know that HTTP requests that aren't encrypted
        # use the layer - RAW
        if packet.haslayer(scapy.Raw):
            print("[+] This Packet contains RAW data sent using HTTP and it might include usernames and passwords")
            # # print(packet.show())
            # this will show the entire packet
            # print(packet[scapy.Raw])
            # this will show the contents of RAW field
            # now, there is a field called load that has specifics and you can use
            # print(packet[scapy.Raw].load)
            rawstr = str(packet[scapy.Raw])
            userpass_detect(rawstr)
        else:
            print("[-] This Packet does not have a RAW field")


def userpass_detect(rawstr):
    # now, there is a field called load that has specifics and you can use
    # print(packet[scapy.Raw].load)
    keywrds = ['username', 'user', 'password', 'pass', 'userpass', 'uname', 'login', 'cred', 'admin', 'user']
    has_username = False
    for keywrd in keywrds:
        if keywrd in rawstr:
            print("[***] Contains Username and Password field")
            has_username = True
            break
    if not has_username:
        print("[-] Does not seem to contain Username Password in RAW field")
    print(rawstr)


def get_url(pack):
    # the url can be found thru the host field and the path field in the HTTP section
    # so what you do it
    url_host = pack[http.HTTPRequest].Host
    url_path = pack[http.HTTPRequest].Path
    url = url_host + url_path
    return url


def verbose_3(pack):
    print("Source IP\t\t" + str(pack[inet.IP].src))
    print("Destination IP\t\t" + str(pack[inet.IP].dst))
    print("Length\t\t\t" + str(pack[inet.IP].len))
    print("Method\t\t\t" + str(pack[http.HTTPRequest].Method))
    print("Cookie\t\t\t" + str(pack[http.HTTPRequest].Cookie))
    print("Date\t\t\t" + str(pack[http.HTTPRequest].Date))


def verbose_4(pack):
    verbose_3(pack)
    print("Source Port\t\t" + str(pack[inet.TCP].sport))
    print("Destination Port\t" + str(pack[inet.TCP].dport))
    print("Seq\t\t\t" + str(pack[inet.TCP].seq))
    print("Ack\t\t\t" + str(pack[inet.TCP].ack))
    print("Flags\t\t\t" + str(pack[inet.TCP].flags))
    print("From\t\t\t" + str(pack[http.HTTPRequest].From))
    print("Origin\t\t\t" + str(pack[http.HTTPRequest].Origin))
    print("Proxy_Authorization\t" + str(pack[http.HTTPRequest].Proxy_Authorization))
    print("Referer\t\t\t" + str(pack[http.HTTPRequest].Referer))


def intro():
    while True:
        print("\n1>  Run Ifconfig to find out interfaces")
        print("2>  Enter Interface and start sniffing")
        choice = int(input("3>  Exit\n"))
        if choice == 1:
            subprocess.call('ifconfig')
        if choice == 2:
            interface = input('Enter Interface\n')
            global verb
            verb = int(input('Enter Verbosity (1 is least, 5 is maximum, and the ideal values are 3 and 4)\n')) or 1
            sniffer(interface)
        if choice == 3:
            exit(1)


intro()
