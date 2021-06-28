package analyzer

import (
	"testing"

	"container/list"
	"fmt"
)

func TestLogStructure(t *testing.T) {
	loginLog := list.New()

	for i := 1; i <= LogMaxRec+3; i++ {
		_ = PushLog(loginLog, fmt.Sprintf("+%011d", i), fmt.Sprintf("127.0.0.%d", i))
	}

	if loginLog.Len() != LogMaxRec {
		t.Errorf("Log length is %d, expected %d", loginLog.Len(), LogMaxRec)
	}

	lastEl, ok := loginLog.Back().Value.(LogRecord)
	if !ok {
		t.Errorf("Log record typecasting error")
	}
	firstEl, ok := loginLog.Front().Value.(LogRecord)
	if !ok {
		t.Errorf("Log record typecasting error")
	}
	if lastEl.Phone != fmt.Sprintf("+%011d", LogMaxRec+3) {
		t.Errorf("Last Phone record is %v, expected %v", lastEl.Phone, fmt.Sprintf("+%011d", LogMaxRec+3))
	}
	if firstEl.Phone != "+00000000004" {
		t.Errorf("First Phone record is %v, expected +00000000004", firstEl.Phone)
	}

	if lastEl.Time > firstEl.Time {
		t.Errorf("Wrong records times: last record Time = %d, first record Time = %d,", lastEl.Time, firstEl.Time)
	}
}

func TestLogRecordRemoval(t *testing.T) {
	loginLog := list.New()

	for i := 1; i <= LogMaxRec; i++ {
		_ = PushLog(loginLog, fmt.Sprintf("+%011d", i), fmt.Sprintf("127.0.0.%d", i))
	}

	var opRes bool
	opRes = RemoveRecFromLog(loginLog, "+00000000000")

	if opRes {
		t.Errorf("False removal reported of the non-existent element +00000000000")
	}

	opRes = RemoveRecFromLog(loginLog, "+00000000002")
	if !opRes {
		t.Errorf("Unable to remove element +00000000002")
	}

	firstEl, ok := loginLog.Front().Value.(LogRecord)
	if !ok {
		t.Errorf("Log record typecasting error")
	}
	secondEl, ok := loginLog.Front().Next().Value.(LogRecord)
	if !ok {
		t.Errorf("Log record typecasting error")
	}

	if firstEl.Phone != "+00000000001" {
		t.Errorf("Removal failure: first Phone record is %v, expected +00000000001", firstEl.Phone)
	}
	if secondEl.Phone != "+00000000003" {
		t.Errorf("Removal failure: second Phone record is %v, expected +00000000003", secondEl.Phone)
	}
}

func TestPatternCheck(t *testing.T) {
	var checkRes bool

	loginLog := list.New()

	_ = PushLog(loginLog, "+79604805265", "127.0.0.1")
	_ = PushLog(loginLog, "+72224805266", "127.0.0.2")
	_ = PushLog(loginLog, "+43214805267", "127.0.0.3")
	_ = PushLog(loginLog, "+41114805268", "127.0.0.4")

	checkRes = CheckPattern(loginLog, "+79604805269")
	if checkRes {
		t.Errorf("Pattern check failure: false positive for Phone +79604805269")
	}

	_ = PushLog(loginLog, "+79604805269", "127.0.0.5")
	_ = PushLog(loginLog, "+79604805270", "127.0.0.6")

	checkRes = CheckPattern(loginLog, "+27774805271")
	if checkRes {
		t.Errorf("Pattern check failure: false positive for Phone +27774805271")
	}

	checkRes = CheckPattern(loginLog, "+79604805275")
	if !checkRes {
		t.Errorf("Pattern check failure: false negative for Phone +79604805275")
	}

	_ = PushLog(loginLog, "+79604805275", "127.0.0.7")
	_ = PushLog(loginLog, "+38884805272", "127.0.0.8")
	_ = PushLog(loginLog, "+41104805200", "127.0.0.9")
	_ = PushLog(loginLog, "+38884806000", "127.0.0.10")

	checkRes = CheckPattern(loginLog, "+38884805273")
	if checkRes {
		t.Errorf("Pattern check failure: false positive for Phone +38884805273")
	}

	checkRes = CheckPattern(loginLog, "+79604805999")
	if !checkRes {
		t.Errorf("Pattern check failure: false negative for Phone +79604805999")
	}

	checkRes = CheckPattern(loginLog, "+41114805111")
	if checkRes {
		t.Errorf("Pattern check failure: false positive for Phone +41114805111")
	}

	_ = PushLog(loginLog, "+29991234000", "127.0.0.11")
	_ = PushLog(loginLog, "+29991234000", "127.0.0.12")
	_ = PushLog(loginLog, "+29991234000", "127.0.0.13")
	checkRes = CheckPattern(loginLog, "+29991234000")
	if checkRes {
		t.Errorf("Pattern check failure for duplicates: false positive for Phone +29991234000")
	}
}
