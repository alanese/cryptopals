package main

import "fmt"

func main() {
	t := NewTwister(1)
	for i := 0; i < 20; i++ {
		fmt.Println(t.Next())
	}
}
