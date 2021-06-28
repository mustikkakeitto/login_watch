// Package analyzer implements functions to detect series built from the particular Phone numbers, used as login data
// Its main purpouse is to prevent brute-force attacks to login pages using sequential search for a valid login
// Analyzer implements its internal in-memory log for storing last reported Phone numbers
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

// LogRecord is an internal log record
type LogRecord struct {
	Phone string
	Ip         string
	Time       int64
	IsDetected bool
}

// CheckPattern performs a search for existing series in the internal log for a number given
// Returns True in case the series was detected, False - otherwise
func CheckPattern(loginLog *list.List, phone string) bool {

	oldestRecTimeAllowed := time.Now().Unix() - LogRecLifeTime

	hitCtr := 0
	for e := loginLog.Back(); e != nil; e = e.Prev() {
		currRec, ok := e.Value.(LogRecord)
		if !ok {
			log.Println("Search: Log record typecasting error occurred.")
			return false
		}

		// don't analyze oldies
		if currRec.Time < oldestRecTimeAllowed {
			break
		}

		// skip duplicates
		if currRec.Phone == phone {
			continue
		}

		// check the pattern
		var levOpts = levenshtein.Options{
			InsCost: 3,
			DelCost: 3,
			SubCost: 1,
			Matches: levenshtein.IdenticalRunes,
		}
		distance := levenshtein.DistanceForStrings([]rune(currRec.Phone), []rune(phone), levOpts)

		if distance <= LewensteinMaxDist {
			hitCtr++
			// TODO: check wether the record has IsDetected flag set: stop search if set, collect the record and proceed with search - otherwise
		}

		if hitCtr >= MaxPatternHits {
			// Max hits reached, stopping
			// TODO: report all the records collected and mark them as reported via IsDetected flag
			return true
		}
	}

	return false
}

// PushLog adds a Phone number to the end of the internal log, alongside with IP
func PushLog(loginLog *list.List, phone string, ip string) bool {
	loginLog.PushBack(LogRecord{phone, ip, time.Now().Unix(), false}) // TODO: set IsDetected to true if a series has been revealed
	if loginLog.Len() > LogMaxRec {
		loginLog.Remove(loginLog.Front())
	}

	// TODO: process possible errors
	return true
}

// RemoveRecFromLog removes a Phone number from the internal log
func RemoveRecFromLog(loginLog *list.List, phone string) bool {
	for e := loginLog.Back(); e != nil; e = e.Prev() {
		currRec, ok := e.Value.(LogRecord)
		if !ok {
			log.Println("Removal: log record typecasting error occurred.")
			return false
		}

		if currRec.Phone == phone {
			loginLog.Remove(e)
			return true
		}
	}

	// TODO: process possible errors
	return false
}

// CleanOldies removes all outdated records from the internal log
func CleanOldies(loginLog *list.List) bool {
	isOldiesFound := false
	oldestRecTimeAllowed := time.Now().Unix() - LogRecLifeTime
	for e := loginLog.Front(); e != nil; e = e.Next() {
		currRec, ok := e.Value.(LogRecord)
		if !ok {
			fmt.Println("Log record typecasting error occurred.")
			return false
		}

		if currRec.Time < oldestRecTimeAllowed {
			isOldiesFound = true
			loginLog.Remove(e)
		} else {
			break
		}
	}

	// TODO: process possible errors
	return isOldiesFound
}
