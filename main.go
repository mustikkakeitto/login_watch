package main

import (
	"container/list"
	"fmt"
	"time"

	"github.com/mustikkakeitto/login_watch/pkg/analyzer"

	"encoding/json"
	"log"
	"net/http"

	"sync"

	"github.com/gorilla/mux"
	rotatelogs "github.com/lestrrat-go/file-rotatelogs"
)

// Output log record
type logRecord struct {
	phone string
	ip    string
	time  int64
}

// REST output
type outputData struct {
	Code        int                 `json:"code"`
	Status      string              `json:"status"`
	Description string              `json:"description"`
	Data        []map[string]string `json:"data"`
}

var listMutex sync.Mutex

// Performs search for the IP given with a series analyzer
// Reports Found Status if positive, Not Found - otherwise
// Saves the IP into the analyzer internal log
func searchAndSaveHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List, repLogger *log.Logger) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        501,
		Status:      "error",
		Description: "n/a",
	}

	var phone string
	var ip string

	vars := mux.Vars(r)
	if reqVar, reqVarExists := vars["phone"]; reqVarExists {
		phone = reqVar
	}
	if reqVar, reqVarExists := vars["ip"]; reqVarExists {
		ip = reqVar
	}

	if phone != "" && ip != "" {
		listMutex.Lock()
		defer listMutex.Unlock()

		if analyzer.CheckPattern(loginLog, phone) {
			oData.Code = 200
			oData.Status = "Found"
			oData.Description = "Success"
			repLogger.Println(ip)
		} else {
			oData.Code = 200
			oData.Status = "Not found"
			oData.Description = "Success"
		}
		_ = analyzer.PushLog(loginLog, phone, ip)
	} else {
		oData.Code = 400
		oData.Description = "No IP provided"
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(oData)
	if err != nil {
		return
	}
}

// Performs search and removal for the IP given in the series analyzer internal log
// Reports Removed Status if positive, Not Found - otherwise
// Used in case of successfull login from the IP, that was processed by the analyzer before
func removalHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        501,
		Status:      "error",
		Description: "n/a",
	}

	var phone string

	vars := mux.Vars(r)
	if reqVar, reqVarExists := vars["phone"]; reqVarExists {
		phone = reqVar

		listMutex.Lock()
		defer listMutex.Unlock()

		if analyzer.RemoveRecFromLog(loginLog, phone) {
			oData.Code = 200
			oData.Status = "Removed"
			oData.Description = "Success"
		} else {
			oData.Code = 200
			oData.Status = "Not found"
			oData.Description = "Success"
		}
	} else {
		oData.Code = 400
		oData.Description = "No IP provided"
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(oData)
	if err != nil {
		return
	}
}

// Performs cleanup of outdated records in the series analyzer internal log
func cleanupHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List) {
	defer serverErrorHandler(w, r)

	resOutput := map[string]string{"code": "200", "status": "unknown", "description": "n/a"}

	listMutex.Lock()
	defer listMutex.Unlock()

	oldiesFoundMsg := "no"
	if oldiesFound := analyzer.CleanOldies(loginLog); oldiesFound {
		oldiesFoundMsg = "yes"
	}
	log.Println("Cleanup done, old records found:", oldiesFoundMsg)
	resOutput = map[string]string{"code": "200", "status": "OK", "description": "Success"}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(resOutput)
	if err != nil {
		return
	}
}

// Shows all records in the series analyzer internal log at the moment
func inspectHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        200,
		Status:      "OK",
		Description: "Success",
	}

	listMutex.Lock()
	defer listMutex.Unlock()

	oData.Data = make([]map[string]string, loginLog.Len())

	i := 0
	for e := loginLog.Back(); e != nil; e = e.Prev() {
		currRec, ok := e.Value.(logRecord)
		if !ok {
			log.Println("Inspect: Log record typecasting error occurred.")
			oData.Code = 501
			oData.Status = "error"
			oData.Description = "Log record typecasting error occurred."
			break
		}

		oData.Data[i] = map[string]string{"phone": currRec.phone, "ip": currRec.ip, "time": fmt.Sprintf("%v", currRec.time)}
		i++
	}

	w.Header().Set("Content-Type", "application/json")
	err := json.NewEncoder(w).Encode(oData)
	if err != nil {
		return
	}
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	nfOutput := map[string]string{"code": "404", "status": "error", "description": "Resource not found"}
	err := json.NewEncoder(w).Encode(nfOutput)
	if err != nil {
		return
	}
}

func serverErrorHandler(w http.ResponseWriter, r *http.Request) {
	errObj := recover()
	if errObj != nil {
		errDescMsg := "Server error"
		if err, ok := errObj.(error); ok {
			errDescMsg += ": " + err.Error()
		}
		w.Header().Set("Content-Type", "application/json")
		nfOutput := map[string]string{"code": "500", "status": "error", "description": errDescMsg}
		err := json.NewEncoder(w).Encode(nfOutput)
		if err != nil {
			return
		}
	}
}

func main() {
	logf, err := rotatelogs.New(
		"log/watcher_common_%Y%m%d.log",
		rotatelogs.WithClock(rotatelogs.UTC),
		rotatelogs.WithMaxAge(24*7*time.Hour),
		rotatelogs.WithRotationTime(24*time.Hour),
	)
	if err != nil {
		log.Printf("Failed to create rotatelogs: %s", err)
		return
	}
	log.SetOutput(logf)

	repLogf, err := rotatelogs.New(
		"log/watcher_ips_%Y%m%d.log",
		rotatelogs.WithClock(rotatelogs.UTC),
		rotatelogs.WithMaxAge(24*7*time.Hour),
		rotatelogs.WithRotationTime(24*time.Hour),
	)
	if err != nil {
		log.Printf("Failed to create rotatelogs: %s", err)
		return
	}
	ipRepLogger := log.New(repLogf, "", log.Ldate|log.Ltime)

	loginLog := list.New()

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/api/v1/search_and_save/{phone}/{ip}", func(w http.ResponseWriter, r *http.Request) {
		searchAndSaveHandler(w, r, loginLog, ipRepLogger)
	}).Methods("GET")

	router.HandleFunc("/api/v1/remove/{phone}", func(w http.ResponseWriter, r *http.Request) {
		removalHandler(w, r, loginLog)
	}).Methods("GET")

	router.HandleFunc("/api/v1/control/inspect", func(w http.ResponseWriter, r *http.Request) {
		inspectHandler(w, r, loginLog)
	}).Methods("GET")

	router.HandleFunc("/api/v1/control/cleanup", func(w http.ResponseWriter, r *http.Request) {
		cleanupHandler(w, r, loginLog)
	}).Methods("GET")

	router.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	log.Println("Operations started.")

	log.Fatal(http.ListenAndServe(":8080", router))
}
