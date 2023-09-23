package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

const (
	snapshotLen = 1024
	promiscuous = false
	timeout     = 30 * time.Second
	basePath    = "./dumps" 
)

func main() {
	if err := os.MkdirAll(basePath, os.ModePerm); err != nil {
		log.Fatal(err)
	}

	var currentFile *os.File
	var pcapWriter *pcapgo.Writer
	var currentDate string

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	sourceIPCounts := make(map[string]int)
	destinationIPCounts := make(map[string]int)

	for _, device := range devices {
		fmt.Printf("Monitoring repeated connections on interfagit ce %s...\n", device.Name)
		handle, err := pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
		if err != nil {
			log.Printf("Error opening interface %s: %v", device.Name, err)
			continue
		}
		defer handle.Close()

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		for packet := range packetSource.Packets() {
			networkLayer := packet.NetworkLayer()
			if networkLayer == nil {
				continue
			}

			srcIP := networkLayer.NetworkFlow().Src().String()
			dstIP := networkLayer.NetworkFlow().Dst().String()

			date := time.Now().Format("2006-01-02")

			if currentDate != date {
				if pcapWriter != nil {
					pcapWriter.Flush()
					currentFile.Close()
				}
				currentDate = date
				fileName := fmt.Sprintf("%s%s.pcap", basePath, date)

				currentFile, err = os.Create(fileName)
				if err != nil {
					log.Fatal(err)
				}

				pcapWriter = pcapgo.NewWriter(currentFile)
				pcapWriter.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
			}

			err := pcapWriter.WritePacket(gopacket.CaptureInfo{
				Timestamp:      packet.Metadata().Timestamp,
				CaptureLength:  packet.Metadata().CaptureLength,
				Length:         packet.Metadata().Length,
			}, packet.Data())

			if err != nil {
				log.Printf("Error writing packet to PCAP file: %v", err)
			}

			sourceIPCounts[srcIP]++
			destinationIPCounts[dstIP]++

			threshold := 5
			if sourceIPCounts[srcIP] > threshold {
				fmt.Printf("Repeated connections from %s on interface %s: %d\n", srcIP, device.Name, sourceIPCounts[srcIP])
			}
			if destinationIPCounts[dstIP] > threshold {
				fmt.Printf("Repeated connections to %s on interface %s: %d\n", dstIP, device.Name, destinationIPCounts[dstIP])
			}
		}
	}
}
