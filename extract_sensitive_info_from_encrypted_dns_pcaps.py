#!/usr/bin/env python3

import os, pyshark

DOT_PCAP_DIR = "/home/allison/Desktop/encrypted-dns-test-env/dot-pcaps"
DOH_PCAP_DIR = "/home/allison/Desktop/encrypted-dns-test-env/doh-pcaps"
DOQ_PCAP_DIR = "/home/allison/Desktop/encrypted-dns-test-env/doq-pcaps"



def generate_transport_layer_str(packet):
    try:
        source_address = packet.ip.src
        source_port = packet[packet.transport_layer].srcport
        destination_address = packet.ip.dst
        destination_port = packet[packet.transport_layer].dstport
        print(f'{source_address}:{source_port} --> {destination_address}:{destination_port}')
    except AttributeError as e:
        pass    



def print_tls_field_if_exists(field_name, packet):
    if field_name in packet.tls.field_names:
        value = packet.tls.get_field_value(field_name)
        print(field_name + ": " + str(value))



def print_quic_field_if_exists(field_name, packet):
    if field_name in packet.quic.field_names:
        value = packet.quic.get_field_value(field_name)
        print(field_name + ": " + str(value))



def dissect_doh_or_dot_packet(packet):
    if(packet.__contains__("tls")):

        if "handshake_type" in packet.tls.field_names:
            handshake_type = packet.tls.get_field_value("handshake_type").int_value
            if handshake_type == 1:
                print("Client Hello")
                generate_transport_layer_str(packet)
                print_tls_field_if_exists("handshake_session_id", packet)
                print_tls_field_if_exists("handshake_extensions_alpn_str", packet)
                print_tls_field_if_exists("handshake_extensions_server_name", packet)
                print_tls_field_if_exists("handshake_random", packet)
                print_tls_field_if_exists("handshake_extensions_key_share_key_exchange", packet)
                print_tls_field_if_exists("handshake_extensions_padding_data", packet)

            elif handshake_type == 2:
                print("Server Hello")
                generate_transport_layer_str(packet)
                print_tls_field_if_exists("record_version", packet)
                print_tls_field_if_exists("record_length", packet)
                print_tls_field_if_exists("handshake_session_id", packet)
                print_tls_field_if_exists("handshake_random", packet)
                print_tls_field_if_exists("handshake_extensions_key_share_key_exchange", packet)
               
        else:
            print("Application Data Packet")
            generate_transport_layer_str(packet)
            print_tls_field_if_exists("record_version", packet)
            print_tls_field_if_exists("record_length", packet)
            print_tls_field_if_exists("app_data_proto", packet)
            print_tls_field_if_exists("app_data", packet)

        print("\n")
            


def dissect_doq_packet(packet):
    print_quic_field_if_exists("connection_number", packet)
    print_quic_field_if_exists("packet_length", packet)
    print_quic_field_if_exists("fixed_bit", packet)

    fields = packet.quic.field_names

    if "long_packet_type" in fields:
        # long packet
        long_packet_type = packet.quic.get_field_value("long_packet_type").int_value
        
        if long_packet_type == 0:
            print("Initial") 
            print_quic_field_if_exists("packet_number", packet)
            print_quic_field_if_exists("version", packet)
            print_quic_field_if_exists("dcid", packet)
            print_quic_field_if_exists("scid", packet)
            print_quic_field_if_exists("token", packet)

            if packet.quic.get_field_value("tls_handshake_type") is not None:
                tls_handshake_msg_type = packet.quic.get_field_value("tls_handshake_type").int_value
                if tls_handshake_msg_type == 1:
                    print("Client Hello")
                elif tls_handshake_msg_type == 2:
                    print("Server Hello")

            print_quic_field_if_exists("tls_handshake_random", packet)
            print_quic_field_if_exists("tls_handshake_extensions_alpn_str", packet)
            print_quic_field_if_exists("tls_handshake_extensions_server_name", packet)

            print_quic_field_if_exists("payload", packet)

        elif long_packet_type == 1:
            print("0-RTT") 
            print_quic_field_if_exists("packet_number", packet)
            print_quic_field_if_exists("version", packet)
            print_quic_field_if_exists("dcid", packet)
            print_quic_field_if_exists("scid", packet)
            print_quic_field_if_exists("payload", packet)

        elif long_packet_type == 2:
            print("Handshake") 
            print_quic_field_if_exists("packet_number", packet)
            print_quic_field_if_exists("version", packet)
            print_quic_field_if_exists("dcid", packet)
            print_quic_field_if_exists("scid", packet)
            print_quic_field_if_exists("payload", packet)

        elif long_packet_type == 3:
            print("Retry")   
            print_quic_field_if_exists("version", packet)
            print_quic_field_if_exists("dcid", packet)
            print_quic_field_if_exists("scid", packet)
            print_quic_field_if_exists("retry_token", packet)    
            print_quic_field_if_exists("retry_integrity_tag", packet)       

    elif "short" in fields:
        # short packet
        print("SHORT PACKET HEADER") 
        print_quic_field_if_exists("packet_number", packet)
        print_quic_field_if_exists("dcid", packet)
        print_quic_field_if_exists("spin_bit", packet)
        print_quic_field_if_exists("remaining_payload", packet)

    print_quic_field_if_exists("padding_length", packet)
    
    print("\n")    



dot_pcap_dir_list = os.listdir(DOT_PCAP_DIR)
doh_pcap_dir_list = os.listdir(DOH_PCAP_DIR)
doq_pcap_dir_list = os.listdir(DOQ_PCAP_DIR)



print("Dissect DNS-over-TLS Network Captures")
for filename in dot_pcap_dir_list:
    if ".pcap" in filename:
        capture = pyshark.FileCapture(DOT_PCAP_DIR + "/" + filename)
        for packet in capture:
            if(packet.__contains__("tls")):
                dissect_doh_or_dot_packet(packet)



print("Dissect DNS-over-HTTPS Network Captures")
for filename in doh_pcap_dir_list:
    if ".pcap" in filename:
        capture = pyshark.FileCapture(DOH_PCAP_DIR + "/" + filename)
        for packet in capture:
            dissect_doh_or_dot_packet(packet)



print("Dissect DNS-over-QUIC Network Captures")
for filename in doq_pcap_dir_list:
    if ".pcap" in filename:
        capture = pyshark.FileCapture(DOQ_PCAP_DIR + "/" + filename)
        for packet in capture:
            if(packet.__contains__("quic")):
                dissect_doq_packet(packet)