package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"time"
)

//C54CollisionTreeNode represents a node in a collision tree
//for an iterated hash
type C54CollisionTreeNode struct {
	State       []byte
	NextMessage []byte
	NextNode    *C54CollisionTreeNode
}

//C54CollisionTree generates a collision tree of 2**k initial states
//(may not be distinct) colliding into a single state
func C54CollisionTree(k int) (leaves []*C54CollisionTreeNode) {
	leaves = make([]*C54CollisionTreeNode, 0)
	for i := 0; i < 1<<k; i++ {
		state := GenerateRandomByteSlice(2)
		tmp := C54CollisionTreeNode{state, nil, nil}
		leaves = append(leaves, &tmp)
	}

	thisLayer := leaves

	for len(thisLayer) > 1 {
		fmt.Printf("Starting layer with %v nodes\n", len(thisLayer)/2)
		prevLayer := thisLayer
		thisLayer = make([]*C54CollisionTreeNode, 0)
		for i := 0; i < len(prevLayer); i += 2 {
			msg1, msg2, newState := C54GenerateCollision(prevLayer[i].State, prevLayer[i+1].State)
			prevLayer[i].NextMessage = msg1
			prevLayer[i+1].NextMessage = msg2
			tmp := C54CollisionTreeNode{newState, nil, nil}
			thisLayer = append(thisLayer, &tmp)
			prevLayer[i].NextNode = &tmp
			prevLayer[i+1].NextNode = &tmp
		}
	}
	return
}

//C54NodeBuildMessage traverses a collision tree upward, starting
//at the given node, and concatenates the messages for the paths
func C54NodeBuildMessage(node *C54CollisionTreeNode) (msg []byte) {
	msg = make([]byte, 0)
	for node.NextNode != nil {
		msg = append(msg, node.NextMessage...)
		node = node.NextNode
	}
	return
}

//C54GenerateCollision generates two messages that collide
//under C52MD from the given initial states
func C54GenerateCollision(initState1, initState2 []byte) (msg1, msg2, finalState []byte) {
	for {
		msg1 = GenerateRandomByteSlice(16)
		msg2 = GenerateRandomByteSlice(16)
		finalState = C52MD(msg1, initState1)
		finalState2 := C52MD(msg2, initState2)
		if bytes.Equal(finalState, finalState2) {
			return
		}
	}
}

//C54GeneratePreimage generates a message with the given prefix that, under the given
//initial state, hashes (via C52MD) to the state at the root of the collision tree
func C54GeneratePreimage(msg, initState []byte, leaves []*C54CollisionTreeNode) []byte {
	finalState := C52MD(msg, initState)

	for {
		bridge := GenerateRandomByteSlice(16)
		bridgeState := C52MD(bridge, finalState)
		for _, v := range leaves {
			if bytes.Equal(v.State, bridgeState) {
				preimage := append(msg, bridge...)
				preimage = append(preimage, C54NodeBuildMessage(v)...)
				return preimage
			}
		}

	}
}

func main() {
	rand.Seed(time.Now().Unix())
	//C50ForgeMsg()
	initState := GenerateRandomByteSlice(2)
	message := []byte("YELLOW SUBMARINE")
	k := 4
	leaves := C54CollisionTree(k)
	tmpNode := leaves[0]
	for tmpNode.NextNode != nil {
		tmpNode = tmpNode.NextNode
	}
	fmt.Printf("Target hash: %x\n", tmpNode.State)
	newMsg := C54GeneratePreimage(message, initState, leaves)
	fmt.Printf("Msg: %x  Hash %x\n", newMsg, C52MD(newMsg, initState))
}
