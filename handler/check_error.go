package main

import "log"

func checkError(err error, msg string) {
	if err != nil {
		log.Panic(msg)
	}
}
