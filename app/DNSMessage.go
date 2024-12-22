package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
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

func (q *Question) Size() int {
	// Type and class are 2 bytes each
	size := 4
	for _, s := range q.Labels {
		size += len(s) + 1 // plus one for the size	field
	}

	return size
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

func (a *Answer) Write(buf []byte) (n int, err error) {
	pos := 0
	// first, read the labels
	labels := make(Labels, 0)
	for buf[pos] != 0 {
		labelLen := int(buf[pos])
		pos++
		labels = append(labels, string(buf[pos:pos+labelLen]))
		pos += labelLen
	}
	a.Name = labels
	pos++ // null byte
	a.Type = RecordType(binary.BigEndian.Uint16(buf[pos : pos+2]))
	pos += 4 // we skip the class and assume it's always 1
	a.TTL = binary.BigEndian.Uint32(buf[pos : pos+4])
	pos += 4
	dataLen := binary.BigEndian.Uint16(buf[pos : pos+2])
	pos += 2
	a.Data = buf[pos : pos+int(dataLen)]
	pos += int(dataLen)
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

type DNSMessage []byte

type Opcode byte

const (
	OpStandard = iota
	OpInverse
	OpStatus
)

func (m *DNSMessage) Id() uint16 {
	return binary.BigEndian.Uint16((*m)[0:2])
}

func (m *DNSMessage) SetId(id uint16) {
	binary.BigEndian.PutUint16((*m)[0:2], id)
}

func (m *DNSMessage) IsQuery() bool {
	return ((*m)[2] & 0b10000000) == 0
}

func (m *DNSMessage) SetIsResponse() {
	(*m)[2] |= 0b10000000
}

func (m *DNSMessage) SetIsQuery() {
	(*m)[2] &= 0b01111111
}

func (m *DNSMessage) Opcode() byte {
	return ((*m)[2] & 0b01111000) >> 3
}

func (m *DNSMessage) SetOpcode(opcode byte) {
	(*m)[2] |= opcode << 3
}

func (m *DNSMessage) IsAuthoritativeAnswer() bool {
	return (*m)[2]&0b00000100 != 0
}

func (m *DNSMessage) IsTruncated() bool {
	return (*m)[2]&0b00000010 != 0
}

func (m *DNSMessage) IsRecursionDesired() bool {
	return (*m)[2]&0b00000001 != 0
}

func (m *DNSMessage) IsRecursionAvailable() bool {
	return (*m)[3]&0b10000000 != 0
}

func (m *DNSMessage) ReservedBits() byte {
	return ((*m)[3] & 0b01110000) >> 4
}

func (m *DNSMessage) ResponseCode() byte {
	return (*m)[3] & 0b00001111
}

func (m *DNSMessage) SetResponseCode(code byte) {
	(*m)[3] = code
}

func (m *DNSMessage) QuestionCount() uint16 {
	return binary.BigEndian.Uint16((*m)[4:6])
}

func (m *DNSMessage) AnswerCount() uint16 {
	return binary.BigEndian.Uint16((*m)[6:8])
}

func (m *DNSMessage) SetAnswerCount(count uint16) {
	binary.BigEndian.PutUint16((*m)[6:8], count)
}

func (m *DNSMessage) AuthorityCount() uint16 {
	return binary.BigEndian.Uint16((*m)[8:10])
}

func (m *DNSMessage) SetAuthorityCount(count uint16) {
	binary.BigEndian.PutUint16((*m)[8:10], count)
}

func (m *DNSMessage) AdditionalRecordCount() uint16 {
	return binary.BigEndian.Uint16((*m)[10:12])
}

func (m *DNSMessage) SetAdditionalRecordCount(count uint16) {
	binary.BigEndian.PutUint16((*m)[10:12], count)
}

func (m *DNSMessage) Questions() ([]Question, int) {
	questions := make([]Question, m.QuestionCount())
	pos := 12
	for i := uint16(0); i < m.QuestionCount(); i++ {
		labels := make([]string, 0)
		oldPos := -1
		for (*m)[pos] != 0 {
			if (*m)[pos]&0b11000000 == 0b11000000 { // this is a compressed label
				offset := (uint16((*m)[pos]&0b00111111) << 8) | uint16((*m)[pos+1])
				oldPos = pos + 2
				pos = int(offset)
			}
			labelLen := int((*m)[pos])
			pos++
			labels = append(labels, string((*m)[pos:pos+labelLen]))
			pos += labelLen
			if oldPos != -1 {
				pos = oldPos
			}
		}

		pos++
		t := binary.BigEndian.Uint16((*m)[pos : pos+2])
		pos += 4
		q := Question{
			Labels:     labels,
			RecordType: RecordType(t),
		}
		questions[i] = q
	}
	return questions, pos
}

func (m *DNSMessage) SetQuestions(questions []Question) int {
	pos := 12
	neededSize := 0
	for _, q := range questions {
		neededSize += q.Size()
	}
	if len(*m)-12 < neededSize {
		*m = append((*m)[:12], make([]byte, neededSize)...)
	}
	binary.BigEndian.PutUint16((*m)[4:6], uint16(len(questions)))
	for _, q := range questions {
		for _, s := range q.Labels {
			(*m)[pos] = byte(len(s))
			pos++
			copy((*m)[pos:], s)
			pos += len(s)
		}
		(*m)[pos] = 0
		pos++
		binary.BigEndian.PutUint16((*m)[pos:pos+2], uint16(q.RecordType))
		pos += 4
	}
	return pos
}

func (m *DNSMessage) SetAnswers(answers []Answer, offset int) (int, error) {
	m.SetAnswerCount(uint16(len(answers)))
	buf := new(bytes.Buffer)
	for _, a := range answers {
		_, err := io.Copy(buf, &a)
		if err != nil && err != io.EOF {
			return len(*m), err
		}
	}

	*m = append((*m)[:offset], buf.Bytes()...)

	return len(*m), nil
}

func (m *DNSMessage) Answers(pos int) ([]Answer, error) {
	answers := make([]Answer, m.AnswerCount())
	for i := uint16(0); i < m.AnswerCount(); i++ {
		a := Answer{}
		slog.Debug("Reading answer", "pos", pos)
		n, err := a.Write((*m)[pos:])
		if err != nil && err != io.EOF {
			return nil, fmt.Errorf("error reading answer: %w", err)
		}
		answers[i] = a
		pos += n
	}
	return answers, nil
}

func (m *DNSMessage) String() string {
	kind := "Response"
	if m.IsQuery() {
		kind = "Query"
	}
	return fmt.Sprintf("%s DNSMessage (id: '%d', opCode: %d, questionCount: %d, answerCount: %d, additionalCount: %d)", kind, m.Id(), m.Opcode(), m.QuestionCount(), m.AnswerCount(), m.AdditionalRecordCount())
}
