package utils

import "log"

func CheckError(err error, msg string) {
	if err != nil {
		log.Panicf(msg, err)
	}
}
