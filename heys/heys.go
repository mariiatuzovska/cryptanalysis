package heys

var (
	Defaultkey = []int{0x7a2b, 0xd01e, 0x1cc9, 0x467f, 0x0553, 0xc131, 0x31cc}
	sBlocks    = []int{0xF, 0x8, 0xE, 0x9, 0x7, 0x2, 0x0, 0xD, 0xC, 0x6, 0x1, 0x5, 0xB, 0x4, 0x3, 0xA}
	iBlocks    = []int{0x6, 0xA, 0x5, 0xE, 0xD, 0xB, 0x9, 0x4, 0x1, 0x3, 0xF, 0xC, 0x8, 0x7, 0x2, 0x0}
)

func EncryptAllWithKey() []int {
	encrypted := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		encrypted[x] = EncryptWithKey(x)
	}
	return encrypted
}

func DecryptAllWithKey() []int {
	decrypted := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		decrypted[x] = DecryptWithKey(x)
	}
	return decrypted
}

func EncryptWithKey(block int) int {
	for i := 0; i < 6; i++ {
		block = permutation(substitution(block^Defaultkey[i], sBlocks))
	}
	return block ^ Defaultkey[6]
}

func DecryptWithKey(block int) int {
	block = block ^ Defaultkey[6]
	for i := 5; i > -1; i-- {
		block = substitution(permutation(block), iBlocks)
	}
	return block
}

func EncryptAll() []int {
	encrypted := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		encrypted[x] = Encrypt(x)
	}
	return encrypted
}

func DecryptAll() []int {
	decrypted := make([]int, 0x10000)
	for x := 0; x < 0x10000; x++ {
		decrypted[x] = Decrypt(x)
	}
	return decrypted
}

func ConvertDataToBlocks(data []byte) []int {
	if len(data)&1 != 0 {
		data = append(data, 0)
	}
	blocks := make([]int, len(data)/2)
	for i := 0; i < len(blocks); i++ {
		blocks[i] = (int(data[i*2+1]) << 8) + int(data[i*2])
	}
	return blocks
}

func ConvertBlocksToData(blocks []int) []byte {
	data := make([]byte, len(blocks)*2)
	for i := 0; i < len(blocks); i++ {
		data[i*2] = byte(blocks[i])
		data[i*2+1] = byte(blocks[i] >> 8)
	}
	return data
}

func Encrypt(block int) int {
	return permutation(substitution(block, sBlocks))
}

func Decrypt(block int) int {
	return substitution(permutation(block), iBlocks)
}

func permutation(block int) int {
	temp := block
	block = 0
	block |= (temp & 0x8421) << 0
	block |= (temp & 0x0842) << 3
	block |= (temp & 0x0084) << 6
	block |= (temp & 0x0008) << 9
	block |= (temp & 0x4210) >> 3
	block |= (temp & 0x2100) >> 6
	block |= (temp & 0x1000) >> 9
	return block
}

func substitution(block int, sBox []int) int {

	b := block

	nibble := (b >> 0) & 0xF
	temp := (sBox[nibble] << 0)
	b &= 0xFFF0
	b |= temp

	nibble = (b >> 4) & 0xF
	temp = (sBox[nibble] << 4)
	b &= 0xFF0F
	b |= temp

	nibble = (b >> 8) & 0xF
	temp = (sBox[nibble] << 8)
	b &= 0xF0FF
	b |= temp

	nibble = (b >> 12) & 0xF
	temp = (sBox[nibble] << 12)
	b &= 0x0FFF
	b |= temp

	return b
}
