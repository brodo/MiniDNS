package main

import (
	"log/slog"
	"net"
	"os"
)

func main() {
	port := "2053"
	resolver := ""
	debug := true

	for i := 1; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--port":
			if i+1 < len(os.Args) {
				port = os.Args[i+1]
				i++
			}
		case "--resolver":
			if i+1 < len(os.Args) {
				resolver = os.Args[i+1]
				i++
			}
		}
		if os.Args[i] == "--debug" {
			debug = true
		}
	}

	if debug {
		lvl := new(slog.LevelVar)
		lvl.Set(slog.LevelDebug)
		logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
			Level: lvl,
		}))
		slog.SetDefault(logger)
		slog.Debug("Debug mode enabled")
	}

	udpAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:"+port)
	if err != nil {
		slog.Error("Failed to resolve UDP address", "error", err)
		return
	}

	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		slog.Error("Failed to bind to address", "error", err)
		return
	}
	defer udpConn.Close()

	var resolverAddr *net.UDPAddr
	var resolverConn *net.UDPConn

	if resolver != "" {
		slog.Debug("Using resolver", "resolver", resolver)
		resolverAddr, err = net.ResolveUDPAddr("udp", resolver)
		if err != nil {
			slog.Error("Failed to resolve resolver address", "error", err)
			return
		}
		resolverConn, err = net.DialUDP("udp", nil, resolverAddr)
		if err != nil {
			slog.Error("Failed to bind to resolver address", "error", err)
			return
		}
		defer resolverConn.Close()
	}

	buf := make([]byte, 512)

	for {
		size, source, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			slog.Error("Error receiving data", "error", err)
			break
		}
		dnsMessage := DNSMessage(buf[:size])
		slog.Debug("Received message", "size", size, "source", source, "dnsMessage", dnsMessage.String())
		if resolverConn != nil {
			msgBuf := make([]byte, 512)
			questions, _ := dnsMessage.Questions()
			answers := make([]Answer, 0)
			rn := 0
			for _, q := range questions {
				copy(msgBuf, buf[:size])
				forwardMsg := DNSMessage(msgBuf[:size])
				pos := forwardMsg.SetQuestions([]Question{q})
				slog.Debug("Forwarding dnsMessage to resolver", "resolver", resolver, "msg", forwardMsg.String())
				_, err = resolverConn.Write(forwardMsg[:pos])
				if err != nil {
					slog.Error("Failed to forward dnsMessage", "error", err)
				}
				rn, err = resolverConn.Read(msgBuf)
				if err != nil {
					slog.Error("Error receiving data from resolver", "error", err)
					return
				}
				dnsResponse := DNSMessage(msgBuf[:rn])
				slog.Debug("Received response from resolver", "size", rn, "msg", dnsResponse.String())
				_, n := dnsResponse.Questions()
				respAnswers, err := dnsResponse.Answers(n)
				if err != nil {
					slog.Error("Failed to get answers", "error", err)
					return
				}
				for _, answer := range respAnswers {
					answers = append(answers, answer)
				}
			}
			slog.Debug("Read questions", "questions", questions)
			msg := DNSMessage(msgBuf[:rn])
			slog.Debug("Building response", "msg", msg.String())
			slog.Debug("setting questions", "questions", questions)
			pos := msg.SetQuestions(questions)
			slog.Debug("setting answers", "answers", answers)
			size, err = msg.SetAnswers(answers, pos)
			if err != nil {
				slog.Error("Failed to set answers", "error", err)
				return
			}

			slog.Debug("Sending response", "response", msg.String())

			_, err = udpConn.WriteToUDP(msgBuf[:size], source)
			if err != nil {
				slog.Error("Failed to forward dnsMessage", "error", err)
				return
			}
			continue
		}

		questions, n := dnsMessage.Questions()
		slog.Debug("Question section", "questions", questions)
		dnsMessage.SetIsResponse()

		if dnsMessage.Opcode() != 0 {
			dnsMessage.SetResponseCode(4)
		}

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
		size, err = dnsMessage.SetAnswers(answers, n)
		if err != nil {
			slog.Debug("Failed to set answers", "error", err)
		}

		slog.Debug("Sending response", "response", string(dnsMessage))
		slog.Debug("Sending message", "response", dnsMessage.String())

		_, err = udpConn.WriteToUDP(dnsMessage, source)
		if err != nil {
			slog.Debug("Failed to send response", "error", err)
		}
	}
}
