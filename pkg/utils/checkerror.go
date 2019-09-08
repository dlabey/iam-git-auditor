package utils

import "log"

func CheckError(err error, msg string) {
	if err != nil {
		log.Panic(msg)
	}
}
