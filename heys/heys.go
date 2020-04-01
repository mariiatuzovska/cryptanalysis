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
