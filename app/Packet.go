package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

type RecordType uint16

//const (
//	ARecord     RecordType = 1  // a host address
//	NSRecord    RecordType = 2  // an authoritative name server
//	MDRecord    RecordType = 3  // a mail destination (Obsolete - use MX)
//	MFRecord    RecordType = 4  // a mail forwarder (Obsolete - use MX)
//	CNAMERecord RecordType = 5  // the canonical name for an alias
//	SOARecord   RecordType = 6  // marks the start of a zone of authority
//	MBRecord    RecordType = 7  // a mailbox domain name (EXPERIMENTAL)
//	MGRecord    RecordType = 8  // a mail group member (EXPERIMENTAL)
//	MRRecord    RecordType = 9  // a mail rename domain name (EXPERIMENTAL)
//	NULLRecord  RecordType = 10 //0 a null RR (EXPERIMENTAL)
//	WKSRecord   RecordType = 11 //1 a well known service description
//	PTRRecord   RecordType = 12 //2 a domain name pointer
//	HINFORecord RecordType = 13 //3 host information
//	MINFORecord RecordType = 14 //4 mailbox or mail list information
//	MXRecord    RecordType = 15 //5 mail exchange
//	TXTRecord   RecordType = 16 //6 text strings
//)

type Question struct {
	Labels     Labels
	RecordType RecordType
	// Type is assumed to be INET
}

func (q *Question) String() string {
	return fmt.Sprintf("%v %d", q.Labels, q.RecordType)
}

type Answer struct {
	Name Labels
	Type RecordType
	TTL  uint32
	Data []byte
}

func (a *Answer) Read(buf []byte) (n int, err error) {
	pos := 0
	for _, s := range a.Name {
		buf[pos] = byte(len(s))
		pos++
		copy(buf[pos:], s)
		pos += len(s)
	}
	buf[pos] = 0
	pos++
	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(a.Type))
	pos += 2
	binary.BigEndian.PutUint16(buf[pos:pos+2], 1) // class, always 1
	pos += 2
	binary.BigEndian.PutUint32(buf[pos:pos+4], a.TTL)
	pos += 4
	binary.BigEndian.PutUint16(buf[pos:pos+2], uint16(len(a.Data)))
	pos += 2
	copy(buf[pos:], a.Data)
	pos += len(a.Data)
	return pos, io.EOF
}

type Labels []string

func (q *Labels) Read(buf []byte) (n int, err error) {
	pos := 0
	for _, s := range *q {
		buf[pos] = byte(len(s))
		pos++
		copy(buf[pos:], s)
		pos += len(s)
		buf[pos] = 0
		pos++
	}
	return pos, nil
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

func (p *Packet) SetResponseCode(code byte) {
	(*p)[3] = code
}

func (p *Packet) QuestionCount() uint16 {
	return binary.BigEndian.Uint16((*p)[4:6])
}

func (p *Packet) AnswerCount() uint16 {
	return binary.BigEndian.Uint16((*p)[6:8])
}

func (p *Packet) SetAnswerCount(count uint16) {
	binary.BigEndian.PutUint16((*p)[6:8], count)
}

func (p *Packet) AuthorityCount() uint16 {
	return binary.BigEndian.Uint16((*p)[8:10])
}

func (p *Packet) SetAuthorityCount(count uint16) {
	binary.BigEndian.PutUint16((*p)[8:10], count)
}

func (p *Packet) AdditionalRecordCount() uint16 {
	return binary.BigEndian.Uint16((*p)[10:12])
}

func (p *Packet) SetAdditionalRecordCount(count uint16) {
	binary.BigEndian.PutUint16((*p)[10:12], count)
}

func (p *Packet) Questions() ([]Question, int) {
	questions := make([]Question, p.QuestionCount())
	pos := 12
	for i := uint16(0); i < p.QuestionCount(); i++ {
		labels := make([]string, 0)
		oldPos := -1
		for (*p)[pos] != 0 {
			if (*p)[pos]&0b11000000 == 0b11000000 { // this is a compressed label
				offset := (uint16((*p)[pos]&0b00111111) << 8) | uint16((*p)[pos+1])
				oldPos = pos + 2
				pos = int(offset)
			}
			labelLen := int((*p)[pos])
			pos++
			labels = append(labels, string((*p)[pos:pos+labelLen]))
			pos += labelLen
			if oldPos != -1 {
				pos = oldPos
			}
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
	return questions, pos
}

func (p *Packet) SetAnswers(answers []Answer, pos int) error {
	p.SetAnswerCount(uint16(len(answers)))
	buf := new(bytes.Buffer)
	for _, a := range answers {
		n, err := io.Copy(buf, &a)
		if err != nil && err != io.EOF {
			return err
		}
		pos += int(n)
	}

	*p = append(*p, buf.Bytes()...)

	return nil
}

func (p *Packet) String() string {
	kind := "Response"
	if p.IsQuery() {
		kind = "Query"
	}
	return fmt.Sprintf("%s Packet (id: '%d', opCode: %d, questionCount: %d, answerCount: %d, additionalCount: %d)", kind, p.Id(), p.Opcode(), p.QuestionCount(), p.AnswerCount(), p.AdditionalRecordCount())
}
