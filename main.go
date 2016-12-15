package main

import(
	"log"
	"net"
	"os"
	"time"
	"github.com/google/gopacket/pcap"
)
var (
	device       string = "eth0"
	snapshot_len int32  = 512
	promiscuous  bool   = false
	err          error
	timeout      time.Duration = 10 * time.Millisecond
	handle       *pcap.Handle
)

func main() {

    ipConnMap, err := GetIPMap()
	if err != nil {
		log.Fatal(err)
        os.Exit(1)
	}

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
        os.Exit(1)
	}
	defer handle.Close()

    iface, err := net.InterfaceByName(device)
    if err != nil {
        log.Fatal(err)
        os.Exit(1)
    }

    for src, dst := range ipConnMap {
        dstIP := net.ParseIP(dst)
        srcIP  := net.ParseIP(src)
        dstMAC, err := ResolveMACByIP(dst, device)

        if err != nil {
            log.Fatal(err)
            os.Exit(1)
        }

        if err := handle.WritePacketData(CreateICMPEchoRequestPacket(iface, srcIP, dstIP, dstMAC)); err != nil {
            log.Fatal(err)
            os.Exit(1)
        }
        time.Sleep(100 * time.Millisecond)
    }
}
