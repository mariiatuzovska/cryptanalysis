package heys

// Heys structure containts key data
type Heys struct {
	key []uint16
}

var _key = []uint16{0x391a, 0xd01e, 0x1cc9, 0x467f, 0x0553, 0xc131, 0x8f42}

// NewHeys returns new Heys structure
func NewHeys(key *[]uint16) *Heys {
	if key != nil {
		return &Heys{
			key: *key,
		}
	}
	return &Heys{
		key: _key,
	}
}

func (heys *Heys) EncryptBlock(block *Block) {
	for r := 0; r < 6; r++ {
		heys.RoundEncryptionBlock(block, r)
	}
	block.Xor(heys.key[6])
}

func (heys *Heys) DecryptBlock(block *Block) {
	block.Xor(heys.key[6])
	for r := 1; r < 7; r++ {
		heys.RoundDecryptionBlock(block, r)
	}
}

func (heys *Heys) RoundEncryptionBlock(block *Block, round int) {
	block.Xor(heys.key[round])
	block.Permuntate()
}

func (heys *Heys) RoundDecryptionBlock(block *Block, round int) {
	block.Unpermuntate()
	block.Xor(heys.key[6-round])
}

func FormData(bytes []byte) []Block {
	blocks := make([]Block, 0)
	if len(bytes)&2 != 0 {
		bytes = append(bytes, byte(0))
	}
	for i := 0; i < len(bytes); i += 2 {
		blocks = append(blocks, Block(uint16(bytes[i])+(uint16(bytes[i+1])<<8)))
	}
	return blocks
}

func DescribeData(blocks *[]Block) []byte {
	b := *blocks
	bytes := make([]byte, 0)
	if len(bytes)&2 != 0 {
		bytes = append(bytes, byte(0))
	}
	for i := 0; i < len(b); i++ {
		bytes = append(bytes, []byte{
			byte(uint16(b[i]) & 0xff),
			byte((uint16(b[i]) >> 8) & 0xff),
		}...)
	}
	return bytes
}

// func (block *Block) SetBytes(bytes []byte) {
// 	*block = Block(uint16(bytes[0]) + (uint16(bytes[1]) << 8))
// }

// func (block *Block) GetBytes() []byte {
// 	return []byte{
// 		byte(uint16(*block) & 0xff),
// 		byte((uint16(*block) >> 8) & 0xff),
// 	}
// }
