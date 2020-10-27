package main

//C49ForgeMessage forges a message transmitting
//1M spacebucks from the original sender to account 563,
//given a message transmitting 1M spacebucks from the original
//sender to any account. Assumes account IDs are three digits.
func C49ForgeMessage(origMessage, origIV []byte) ([]byte, []byte) {
	newBlock := make([]byte, 16)
	newIV := make([]byte, 16)
	copy(newBlock, origMessage)
	copy(newIV, origIV)

	myAcct := []byte("563")
	origTo := origMessage[12:15]
	flipper, _ := XorBufs(myAcct, origTo)

	newIvChunk, _ := XorBufs(flipper, origIV[12:15])
	newIV[12] = newIvChunk[0]
	newIV[13] = newIvChunk[1]
	newIV[14] = newIvChunk[2]

	newBlock[12] = byte('5')
	newBlock[13] = byte('6')
	newBlock[14] = byte('3')
	return append(newBlock, origMessage[16:]...), newIV

}
