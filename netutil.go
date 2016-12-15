package main

import (
	"log"
	"net"
	"strings"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"time"
	"errors"
	"bytes"
)

// ARPパケットの作成
func CreateARPPacket(iface *net.Interface, srcAddr net.IP, dstAddr net.IP) []byte {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: srcAddr.To4(),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    dstAddr.To4(),
	}

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &arp)

    return buf.Bytes()
}

// ICMPリクエストパケットの作成
func CreateICMPEchoRequestPacket(iface *net.Interface, srcAddr net.IP, dstAddr net.IP, mac string) []byte {
    dstMac, _ := net.ParseMAC(mac)
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := layers.IPv4{
		SrcIP:    srcAddr.To4(),
		DstIP:    dstAddr.To4(),
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolICMPv4,
    }

	icmp4 := layers.ICMPv4{
        TypeCode: layers.CreateICMPv4TypeCode(8, 00),
        Seq:      1,
    }

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	gopacket.SerializeLayers(buf, opts, &eth, &ip4, &icmp4)

    return buf.Bytes()
}

// Read ARPパケット
func ReadARPPacket(handle *pcap.Handle, dstIP []byte) (net.HardwareAddr, error) {
    start := time.Now()
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout reading ARP reply")
		}

        
        if err := handle.SetBPFFilter("arp"); err != nil {
            log.Fatal(err)
        }

		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			if bytes.Equal(arp.SourceProtAddress, dstIP) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func ResolveMACByIP(targetIP string, deviceName string) (string, error) {
    var(
        snapshot_len int32  = 512
        promiscuous  bool   = false
        err          error
        timeout      time.Duration = 10 * time.Millisecond
        handle       *pcap.Handle
    )
    iface, _ := net.InterfaceByName(deviceName)
    srcIP := net.ParseIP(GetDeviceIP(deviceName)[0])
    dstIP   := net.ParseIP(targetIP)

	handle, err = pcap.OpenLive(deviceName, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
        handle.Close()
        return "", err
	}
	defer handle.Close()

    go handle.WritePacketData(CreateARPPacket(iface, srcIP, dstIP))
    
    dstMAC, err := ReadARPPacket(handle, dstIP.To4())
	if err != nil {
		log.Fatal(err)
        handle.Close()
        return "", err
	}
    return dstMAC.String(), nil
}


// NIC(ex: eth0)のIPアドレスを取ってくる
func GetDeviceIP(device string) []string{
    iface, _ := net.InterfaceByName(device)
	ips, _ := iface.Addrs()
    return strings.Split(ips[0].String(), "/")[:1]
}
