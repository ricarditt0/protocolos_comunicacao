#!/usr/bin/env python3
import os
import sys

from scapy.all import (
	TCP,
	IP,
	FieldLenField,
	FieldListField,
	IntField,
	IPOption,
	ShortField,
	get_if_list,
	Packet,
	Ether,
	BitField,
	bind_layers,
	PacketListField,
	sniff
)
from scapy.layers.inet import _IPOption_HDR


def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class INT_filho(Packet):
    fields_desc = [
        BitField("ID_Switch", 0, 32),
        BitField("Porta_Entrada", 0, 9),
        BitField("Porta_Saida", 0, 9),
        BitField("Timestamp_ingress", 0, 48),
		BitField("Timestamp_egress",0 ,48),
        BitField("padding", 0, 6)
    ]

    def extract_padding(self, p):
        return "", p

class INT(Packet):
    name = "INT"
    fields_desc = [
        BitField("Quantidade_Filhos", 0, 32),
        BitField("next_header", 0, 16),
		BitField("MTU_Overflow", 0, 8),
        PacketListField("filhos", [], INT_filho,
                        count_from=lambda pkt: pkt.Quantidade_Filhos)
    ]


def handle_pkt(pkt):
    if TCP in pkt and pkt[TCP].dport == 1234:
        print("got a packet")

        # Verifica se o campo MTU_Overflow é igual a 1
        if INT in pkt and pkt[INT].MTU_Overflow == 1:
            print("Warning: MTU overflow detected!")
        else:
            print("No overflow detected")

        pkt.show2()

        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir('/sys/class/net/') if 'eth' in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()

    bind_layers(Ether, INT, type=0x88B7)
    bind_layers(INT, IP, next_header=0x0800)

    sniff(iface=iface, prn=lambda x: handle_pkt(x))

if __name__ == '__main__':
    main()
