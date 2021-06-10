// Package analyzer implements functions to detect series built from the particular phone numbers, used as login data
// Its main purpouse is to prevent brute-force attacks to login pages using sequential search for a valid login
// Analyzer implements its internal in-memory log for storing last reported phone numbers
package analyzer

import (
	"container/list"
	"fmt"
	"time"

	"github.com/texttheater/golang-levenshtein/levenshtein"

	"log"
)

const LogMaxRec = 100
const MaxPatternHits = 3
const LewensteinMaxDist = 3
const LogRecLifeTime = 600 // 10 minutes
// const CleanupInterval = 18000 // 30 minutes

type logRecord struct {
	phone string
	ip    string
	time  int64
}

// Performs a search for existing series in the internal log for a number given
// Returns True in case the series was detected, False - otherwise
func CheckPattern(loginLog *list.List, phone string) bool {

	oldestRecTimeAllowed := time.Now().Unix() - LogRecLifeTime

	hitCtr := 0
	for e := loginLog.Back(); e != nil; e = e.Prev() {
		currRec, ok := e.Value.(logRecord)
		if !ok {
			log.Println("Search: Log record typecasting error occurred.")
			return false
		}

		// don't analyze oldies
		if currRec.time < oldestRecTimeAllowed {
			break
		}

		// skip duplicates
		if currRec.phone == phone {
			continue
		}

		// check the pattern
		var levOpts = levenshtein.Options{
			InsCost: 3,
			DelCost: 3,
			SubCost: 1,
			Matches: levenshtein.IdenticalRunes,
		}
		distance := levenshtein.DistanceForStrings([]rune(currRec.phone), []rune(phone), levOpts)

		if distance <= LewensteinMaxDist {
			hitCtr++
		}

		if hitCtr >= MaxPatternHits {
			// Max hits reached, stopping
			return true
		}
	}

	return false
}

// Adds a phone number to the end of the interal log, alongside with IP
func PushLog(loginLog *list.List, phone string, ip string) bool {
	loginLog.PushBack(logRecord{phone, ip, time.Now().Unix()})
	if loginLog.Len() > LogMaxRec {
		loginLog.Remove(loginLog.Front())
	}

	// TODO: process possible errors
	return true
}

// Removes a phone number from the internal log
func RemoveRecFromLog(loginLog *list.List, phone string) bool {
	for e := loginLog.Back(); e != nil; e = e.Prev() {
		currRec, ok := e.Value.(logRecord)
		if !ok {
			log.Println("Removal: log record typecasting error occurred.")
			return false
		}

		if currRec.phone == phone {
			loginLog.Remove(e)
			return true
		}
	}

	// TODO: process possible errors
	return false
}

// Removes all outdated records from the internal log
func CleanOldies(loginLog *list.List) bool {
	isOldiesFound := false
	oldestRecTimeAllowed := time.Now().Unix() - LogRecLifeTime
	for e := loginLog.Front(); e != nil; e = e.Next() {
		currRec, ok := e.Value.(logRecord)
		if !ok {
			fmt.Println("Log record typecasting error occurred.")
			return false
		}

		if currRec.time < oldestRecTimeAllowed {
			isOldiesFound = true
			loginLog.Remove(e)
		} else {
			break
		}
	}

	// TODO: process possible errors
	return isOldiesFound
}
