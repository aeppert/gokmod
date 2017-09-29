// Aaron Eppert - 2017
// golang wrapper around libkmod with lsmod as an example
//
package main

import "C"
import (
	"fmt"

	"github.com/aeppert/gokmod"
)

func lsmod() error {
	list, err := gokmod.GetKModList(false)

	fmt.Println(list)
	if err == nil {
		fmt.Println("Module                  Size  Used by")

		for m := range list {
			fmt.Printf("%-19s %8v  %d", list[m].Name, list[m].Size, list[m].UseCount)

			first := true
			if list[m].Holders != nil {
				for h := range list[m].Holders {
					if !first {
						fmt.Printf(",")
					} else {
						fmt.Printf(" ")
						first = false
					}

					fmt.Printf("%s", list[m].Holders[h])
				}
			}

			fmt.Println()
		}
	}

	return err
}

func main() {
	err := lsmod()
	if err != nil {
		fmt.Println(err)
	}
}
