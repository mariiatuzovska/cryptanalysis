package heys

import (
	"log"
	"os"

	"github.com/mariiatuzovska/cryptanalysis/util"
)

var (
	SBlock []byte = []byte{0xf, 0x8, 0xe, 0x9, 0x7, 0x2, 0x0, 0xd, 0xc, 0x6, 0x1, 0x5, 0xb, 0x4, 0x3, 0xa}
	IBlock []byte = []byte{0x6, 0xa, 0x5, 0xe, 0xd, 0xb, 0x9, 0x4, 0x1, 0x3, 0xf, 0xc, 0x8, 0x7, 0x2, 0x0}
)

type Heys struct {
	SBlock, IBlock []byte
	KeyFile        string
	key            []byte
}

func New(keyFile string) *Heys {

	_, err := os.Open(keyFile)
	if err != nil {
		_, err := os.Create(keyFile)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("%s created new empty", keyFile)
	}
	h := &Heys{
		SBlock:  SBlock,
		IBlock:  IBlock,
		KeyFile: keyFile,
	}
	h.key, err = h.GetKey()
	if err != nil {
		log.Fatal(err)
	}

	return h
}

func (h *Heys) Encrypt(plainText []byte) (cipherText []byte, err error) {

	if len(plainText)%2 == 1 {
		cipherText = make([]byte, len(plainText)+1)
	} else {
		cipherText = make([]byte, len(plainText))
	}
	for i := 0; i < len(plainText); i++ {
		cipherText[i] = plainText[i]
	}
	for i := 0; i < len(cipherText)/2; i++ {
		block := h.Word(cipherText, i)
		block, err = h.EncryptBlock(block)
		if err != nil {
			return
		}
		h.SetWord(cipherText, block, i)
	}

	return
}

func (h *Heys) RoundEncryptionBlock(block uint16, round int) (uint16, error) {

	roundKey := h.Word(h.key, round)
	block = block ^ roundKey
	if round != 6 {
		nibble := h.Nibbles(block)
		for k := 0; k < 4; k++ {
			nibble[k] = h.SBlock[nibble[k]]
		}
		block = h.GenereWord(nibble)
	}

	return block, nil
}

func (h *Heys) EncryptBlock(block uint16) (uint16, error) {

	var err error
	for round := 0; round < 7; round++ {
		block, err = h.RoundEncryptionBlock(block, round)
		if err != nil {
			return 0, err
		}
	}

	return block, nil
}

func (h *Heys) Decrypt(cipherText []byte) (plainText []byte, err error) {

	plainText = make([]byte, len(cipherText))
	for i := 0; i < len(plainText); i++ {
		plainText[i] = cipherText[i]
	}
	for i := 0; i < len(plainText)/2; i++ {
		block := h.Word(plainText, i)
		block, err = h.DecryptBlock(block)
		if err != nil {
			return
		}
		h.SetWord(plainText, block, i)
	}

	return
}

func (h *Heys) RoundDecryptionBlock(block uint16, round int) (uint16, error) {

	if round != 0 {
		nibble := h.Nibbles(block)
		for k := 0; k < 4; k++ {
			nibble[k] = h.IBlock[nibble[k]]
		}
		block = h.GenereWord(nibble)
	}
	roundKey := h.Word(h.key, 6-round)
	block = block ^ roundKey

	return block, nil
}

func (h *Heys) DecryptBlock(block uint16) (uint16, error) {

	var err error
	for round := 0; round < 7; round++ {
		block, err = h.RoundDecryptionBlock(block, round)
		if err != nil {
			return 0, err
		}
	}

	return block, nil
}

func (h *Heys) GenereKey() []byte {

	myKey := util.GenereBytes(14)
	util.SetStringToFile(myKey, h.KeyFile)
	h.key = myKey

	return myKey
}

func (h *Heys) GetKey() ([]byte, error) {
	return util.GetBytesFromFile(h.KeyFile)
}

func (h *Heys) Word(bytes []byte, index int) uint16 {
	return (uint16(bytes[index*2]) << 8) + uint16(bytes[index*2+1])
}

func (h *Heys) SetWord(bytes []byte, w uint16, index int) {
	bytes[index*2+1] = byte(w & 0xff)
	bytes[index*2] = byte((w >> 8) & 0xff)
}

func (h *Heys) Nibbles(word uint16) (arr [4]byte) {

	var temp uint16 = word
	for i := 0; i < 4; i++ {
		arr[3-i] = byte(temp & 0xf)
		temp >>= 4
	}
	return
}

func (h *Heys) Nibble(word uint16, index int) byte {
	temp := h.Nibbles(word)
	return temp[index]
}

func (h *Heys) GenereWord(nibble [4]byte) (word uint16) {

	word = 0
	var d uint16 = 1
	for i := 0; i < 4; i++ {
		word += uint16(nibble[3-i]) * d
		d <<= 4
	}

	return
}
