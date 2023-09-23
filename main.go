package main

import (
    "fmt"
    "log"
    "os"
    "path/filepath"
    "time"
    "net"
    "sync"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
    "github.com/go-resty/resty"
)

const (
    snapshotLen = 1024 promiscuous = true timeout = 30 * time.Second basePath = "./dumps"
    discordWebhookURL = "https://discord.com/api/webhooks/1155004446112239706/qhujL9opqnqicZVBmFfgg8QCwyBBZ30FPkiFBzau05SuvBV1mV_MGhWdnd1qnqLykNTW"
    repeatedConnectionThreshold = 30 outgoingSSHSubnet = "23.142.248.0/24"
    maxLogInterval = time.Minute
)

var sourceIPCounts = make(map[string] int)
var destinationIPCounts = make(map[string] int)
var connectionLogs = make(map[string] time.Time)
var connectionLogsMutex sync.Mutex

func sendToDiscord(message string) {
    client: = resty.New()
    _,
    err: = client.R().
    SetHeader("Content-Type", "application/json").
    SetBody(map[string] string {
        "content": message
    }).
    Post(discordWebhookURL)
    if err != nil {
        log.Printf("Error sending message to Discord: %v", err)
    }
}

func createPCAPWriter(fileName string)( * os.File, * pcapgo.Writer, error) {
    filePath: = filepath.Join(basePath, fileName)
    currentFile,
    err: = os.Create(filePath)
    if err != nil {
        return nil, nil, err
    }
    pcapWriter: = pcapgo.NewWriter(currentFile)
    pcapWriter.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
    return currentFile,
    pcapWriter,
    nil
}

func processPacket(packet gopacket.Packet, deviceName string) {
    networkLayer: = packet.NetworkLayer()
    if networkLayer == nil {
        return
    }

    srcIP: = networkLayer.NetworkFlow().Src().String()
    dstIP: = networkLayer.NetworkFlow().Dst().String()

        date: = time.Now().Format("2006-01-02")
    fileName: = fmt.Sprintf("%s.pcap", date)

    if currentDate != date {
        if pcapWriter != nil {
            currentFile.Close()
        }
        currentDate = date

        var err error
        currentFile, pcapWriter, err = createPCAPWriter(fileName)
        if err != nil {
            log.Fatal(err)
        }
    }

    err: = pcapWriter.WritePacket(gopacket.CaptureInfo {
        Timestamp: packet.Metadata().Timestamp,
        CaptureLength: packet.Metadata().CaptureLength,
        Length: packet.Metadata().Length,
    }, packet.Data())

    if err != nil {
        log.Printf("Error writing packet to PCAP file: %v", err)
    }

    if tcpLayer: = packet.Layer(layers.LayerTypeTCP);tcpLayer != nil {
        tcp, _: = tcpLayer.( * layers.TCP)
        srcPort: = tcp.SrcPort
        dstPort: = tcp.DstPort

        if dstPort == layers.TCPPort(22) {
            direction: = "outgoing"

                if isIPInRange(srcIP, outgoingSSHSubnet) {
                connectionKey: = fmt.Sprintf("%s:%s:%s:%s", srcIP, dstIP, srcPort.String(), dstPort.String())

                    connectionLogsMutex.Lock()
                lastLogTime,
                exists: = connectionLogs[connectionKey]
                if !exists || time.Since(lastLogTime) > maxLogInterval {
                    sshAlert: = fmt.Sprintf("SSH `%s` connection detected from `%s` to `%s` on interface `%s`.", direction, srcIP, dstIP, deviceName)
                    sendToDiscord(sshAlert)
                    connectionLogs[connectionKey] = time.Now()
                }
                connectionLogsMutex.Unlock()
            }
        }

        if sourceIPCounts[srcIP] > repeatedConnectionThreshold || destinationIPCounts[dstIP] > repeatedConnectionThreshold {
            err: = pcapWriter.WritePacket(gopacket.CaptureInfo {
                Timestamp: packet.Metadata().Timestamp,
                CaptureLength: packet.Metadata().CaptureLength,
                Length: packet.Metadata().Length,
            }, packet.Data())
            if err != nil {
                log.Printf("Error writing packet to PCAP file: %v", err)
            }
        }
    }

    sourceIPCounts[srcIP] ++
    destinationIPCounts[dstIP] ++
}

func isIPInRange(ipStr string, subnetStr string) bool {
    ip: = net.ParseIP(ipStr)
    _,
    subnet,
    err: = net.ParseCIDR(subnetStr)
    if err != nil {
        log.Printf("Error parsing CIDR: %v", err)
        return false
    }
    return subnet.Contains(ip)
}

func printConnectionsOverThreshold() {
    for {
        time.Sleep(time.Minute)
        fmt.Println("Connections over the threshold:")
        for ip, count: = range sourceIPCounts {
            if count > repeatedConnectionThreshold {
                fmt.Printf("%s -> Outgoing Connections: %d\n", ip, count)
            }
        }
        for ip, count: = range destinationIPCounts {
            if count > repeatedConnectionThreshold {
                fmt.Printf("%s -> Incoming Connections: %d\n", ip, count)
            }
        }
    }
}


var currentDate string
var currentFile * os.File
var pcapWriter * pcapgo.Writer

func main() {
    if err: = os.MkdirAll(basePath, os.ModePerm);
    err != nil {
        log.Fatal(err)
    }

    go printConnectionsOverThreshold()

    devices, err: = pcap.FindAllDevs()
    if err != nil {
        log.Fatal(err)
    }

    for _, device: = range devices {
        fmt.Printf("Monitoring connections on interface %s...\n", device.Name)
        handle, err: = pcap.OpenLive(device.Name, snapshotLen, promiscuous, timeout)
        if err != nil {
            log.Printf("Error opening interface %s: %v", device.Name, err)
            continue
        }
        defer handle.Close()

        packetSource: = gopacket.NewPacketSource(handle, handle.LinkType())

        for packet: = range packetSource.Packets() {
            processPacket(packet, device.Name)
        }
    }
}