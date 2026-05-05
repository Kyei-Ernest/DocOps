package main

import "fmt"

func main() {
    ages := make(map[string]int)

    // populate
    ages["Ernest"] = 21
    ages["Ama"] = 19
    ages["Kojo"] = 25

    a, b := ages["Ernest"]

	fmt.Println(a, b)
}