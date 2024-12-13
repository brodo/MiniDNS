package main

import (
	"fmt"
	"log/slog"
	"net"
)

func main() {
	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:2053")
	if err != nil {
		fmt.Println("Failed to resolve UDP address:", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		fmt.Println("Failed to bind to address:", err)
		return
	}
	defer udpConn.Close()

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("Error receiving data", "error", err)
			break
		}
		packet := Packet(buf[:size])
		slog.Info("Received message", "size", size, "source", source, "packet", packet.String())
		questions, n := packet.Questions()
		slog.Info("Question section", "questions", questions)
		packet.SetIsResponse()

		answers := make([]Answer, 0)

		for _, q := range questions {
			answer := Answer{
				Name: q.Labels,
				Type: q.RecordType,
				TTL:  60,
				Data: []byte{1, 2, 3, 4},
			}
			answers = append(answers, answer)
		}
		err = packet.SetAnswers(answers, n)
		if err != nil {
			slog.Info("Failed to set answers", "error", err)
		}

		slog.Info("Sending response", "response", string(packet))
		slog.Info("Sending message", "response", packet.String())

		_, err = udpConn.WriteToUDP(packet, source)
		if err != nil {
			slog.Info("Failed to send response", "error", err)
		}
	}
}
