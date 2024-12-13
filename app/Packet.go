package main

import (
	"encoding/binary"
	"fmt"
)

type RecordType uint16

const (
	ARecord     RecordType = 1  // a host address
	NSRecord    RecordType = 2  // an authoritative name server
	MDRecord    RecordType = 3  // a mail destination (Obsolete - use MX)
	MFRecord    RecordType = 4  // a mail forwarder (Obsolete - use MX)
	CNAMERecord RecordType = 5  // the canonical name for an alias
	SOARecord   RecordType = 6  // marks the start of a zone of authority
	MBRecord    RecordType = 7  // a mailbox domain name (EXPERIMENTAL)
	MGRecord    RecordType = 8  // a mail group member (EXPERIMENTAL)
	MRRecord    RecordType = 9  // a mail rename domain name (EXPERIMENTAL)
	NULLRecord  RecordType = 10 //0 a null RR (EXPERIMENTAL)
	WKSRecord   RecordType = 11 //1 a well known service description
	PTRRecord   RecordType = 12 //2 a domain name pointer
	HINFORecord RecordType = 13 //3 host information
	MINFORecord RecordType = 14 //4 mailbox or mail list information
	MXRecord    RecordType = 15 //5 mail exchange
	TXTRecord   RecordType = 16 //6 text strings

)

type Question struct {
	Labels     []string
	RecordType RecordType
	// Type is assumed to be INET
}

type Packet []byte

type Opcode byte

const (
	OpStandard = iota
	OpInverse
	OpStatus
)

func (p *Packet) Id() uint16 {
	return binary.BigEndian.Uint16((*p)[0:2])
}

func (p *Packet) SetId(id uint16) {
	binary.BigEndian.PutUint16((*p)[0:2], id)
}

func (p *Packet) IsQuery() bool {
	return ((*p)[2] & 0b10000000) == 0
}

func (p *Packet) SetIsResponse() {
	(*p)[2] |= 0b10000000
}

func (p *Packet) SetIsQuery() {
	(*p)[2] &= 0b01111111
}

func (p *Packet) Opcode() byte {
	return ((*p)[2] & 0b01111000) >> 3
}

func (p *Packet) SetOpcode(opcode byte) {
	(*p)[2] |= opcode << 3
}

func (p *Packet) IsAuthoritativeAnswer() bool {
	return (*p)[2]&0b00000100 != 0
}

func (p *Packet) IsTruncated() bool {
	return (*p)[2]&0b00000010 != 0
}

func (p *Packet) IsRecursionDesired() bool {
	return (*p)[2]&0b00000001 != 0
}

func (p *Packet) IsRecursionAvailable() bool {
	return (*p)[3]&0b10000000 != 0
}

func (p *Packet) ReservedBits() byte {
	return ((*p)[3] & 0b01110000) >> 4
}

func (p *Packet) ResponseCode() byte {
	return (*p)[3] & 0b00001111
}

func (p *Packet) QuestionCount() uint16 {
	return binary.BigEndian.Uint16((*p)[4:6])
}

func (p *Packet) AnswerCount() uint16 {
	return binary.BigEndian.Uint16((*p)[7:9])
}

func (p *Packet) AdditionalRecordCount() uint16 {
	return binary.BigEndian.Uint16((*p)[10:12])

}

func (p *Packet) Questions() []Question { // todo: Make this return "Question"
	questions := make([]Question, p.QuestionCount())
	pos := 12
	for i := uint16(0); i < p.QuestionCount(); i++ {
		labels := make([]string, 0)
		for (*p)[pos] != 0 {
			labelLen := int((*p)[pos])
			pos++
			labels = append(labels, string((*p)[pos:pos+labelLen]))
			pos += labelLen
		}
		pos++
		t := binary.BigEndian.Uint16((*p)[pos : pos+2])
		pos += 4
		q := Question{
			Labels:     labels,
			RecordType: RecordType(t),
		}
		questions[i] = q
	}

	return questions
}

func (p *Packet) String() string {
	kind := "Response"
	if p.IsQuery() {
		kind = "Query"
	}
	return fmt.Sprintf("%s Packet (id: '%d', opCode: %d, questionCount: %d, answerCount: %d, additionalCount: %d)", kind, p.Id(), p.Opcode(), p.QuestionCount(), p.AnswerCount(), p.AdditionalRecordCount())
}
