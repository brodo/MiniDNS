package main

import "encoding/binary"

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
	return ((*p)[2] & 0b10000000) != 0
}

func (p *Packet) SetIsQuery() {
	(*p)[2] |= 0b10000000
}

func (p *Packet) SetIsResponse() {
	(*p)[2] &= 0b11111110
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
