package main

import (
	"io/ioutil"

	"gopkg.in/yaml.v3"

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

// Config data
type AppConfig struct {
	Clients map[string]struct {
		ClientKey string `yaml:"key"`
	} `yaml:"clients"`
}

// REST output
type outputData struct {
	Code        int                 `json:"code"`
	Status      string              `json:"status"`
	Description string              `json:"description"`
	Data        []map[string]string `json:"data"`
}

const (
	ReportingReasonSequence = "sequence"
	ReportingReasonOther    = "other"
)

// Reads app config
func GetConfig() (*AppConfig, error) {
	content, err := ioutil.ReadFile("data/app_cfg.yml")
	if err != nil {
		log.Fatalf("Failed to read from the config: %v", err)
	}

	cfg := AppConfig{}
	err = yaml.Unmarshal([]byte(content), &cfg)
	if err != nil {
		log.Fatalf("Failed to parse the config: %v", err)
	}

	return &cfg, nil
}

var listMutex sync.Mutex

// Performs search for the IP given with a series analyzer
// Reports Found Status and saves into the bad IPs report log - if positive, Not Found - otherwise
// Saves the IP into the analyzer internal log
func searchAndSaveHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List, badIPsRepLogger *log.Logger) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        501,
		Status:      "error",
		Description: "n/a",
	}

	var phone string
	var ip string

	vars := mux.Vars(r)
	phone = vars["phone"]
	ip = vars["ip"]

	listMutex.Lock()
	defer listMutex.Unlock()

	if analyzer.CheckPattern(loginLog, phone) {
		oData.Code = 200
		oData.Status = "Found"
		oData.Description = "Success"
		badIPsRepLogger.Println(ip, ReportingReasonSequence)
	} else {
		oData.Code = 200
		oData.Status = "Not found"
		oData.Description = "Success"
	}
	_ = analyzer.PushLog(loginLog, phone, ip)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(oData)
}

// Saves bad IP into the bad IPs report log with a reason given
// Reports Saved Status
func reportBadIPHandler(w http.ResponseWriter, r *http.Request, badIPsRepLogger *log.Logger) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        501,
		Status:      "error",
		Description: "n/a",
	}

	var ip string
	repReason := ReportingReasonOther

	vars := mux.Vars(r)
	ip = vars["ip"]
	if reqVar, reqVarExists := vars["reason"]; reqVarExists {
		repReason = reqVar
	}

	oData.Code = 200
	oData.Status = "Saved"
	oData.Description = "Success"
	badIPsRepLogger.Println(ip, repReason)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(oData)
}

// Performs search and removal for the IP given in the series analyzer internal log
// Reports Removed Status if positive, Not Found - otherwise
// Used in case of successful login from the IP, that was processed by the analyzer before
func removalHandler(w http.ResponseWriter, r *http.Request, loginLog *list.List) {
	defer serverErrorHandler(w, r)

	oData := outputData{
		Code:        501,
		Status:      "error",
		Description: "n/a",
	}

	vars := mux.Vars(r)
	phone := vars["phone"]
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

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(oData)
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
	_ = json.NewEncoder(w).Encode(resOutput)
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
		currRec, ok := e.Value.(analyzer.LogRecord)
		if !ok {
			log.Println("Inspect: Log record typecasting error occurred. e = ", e)
			oData.Code = 501
			oData.Status = "error"
			oData.Description = "Log record typecasting error occurred."
			break
		}

		oData.Data[i] = map[string]string{"phone": currRec.Phone, "ip": currRec.Ip, "time": fmt.Sprintf("%v", currRec.Time)}
		i++
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(oData)
}

func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	nfOutput := map[string]string{"code": "404", "status": "error", "description": "Resource not found"}
	_ = json.NewEncoder(w).Encode(nfOutput)
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
		_ = json.NewEncoder(w).Encode(nfOutput)
	}
}

// TODO: Prevent unauthorized access procedure
/*
func filterUnauthReqsOut(clientKey string, clientsK2IMap *map[string]string{}, w *http.ResponseWriter, r *http.Request) {
	if clientID, clientExists := clientsK2IMap[clientKey]; clientExists {
		log.Println("Processing request for the client " + clientID)

	} else {
		oData := outputData{
			Code:        403,
			Status:      "error",
			Description: "Wrong key provided",
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(oData)
	}
}
*/

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

	appCfg, _ := GetConfig()
	clientsK2IMap := map[string]string{} // Clients Key to ID map
	hitsLogs := map[string]*list.List{}
	for currClientID, currClientCfg := range appCfg.Clients {
		clientsK2IMap[currClientCfg.ClientKey] = currClientID
		hitsLogs[currClientID] = list.New() // create a hit log for each of the clients
		log.Printf("A Hit Log created for a client %s", currClientID)
	}

	router := mux.NewRouter().StrictSlash(true)

	router.HandleFunc("/api/v1/search_and_save/{phone}/{ip}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clientKey := vars["client_key"]

		if clientID, clientExists := clientsK2IMap[clientKey]; clientExists {
			log.Println("Processing request for the client " + clientID)
			searchAndSaveHandler(w, r, hitsLogs[clientID], ipRepLogger)
		} else {
			oData := outputData{
				Code:        403,
				Status:      "error",
				Description: "Wrong key provided",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oData)
		}
	}).Queries("client_key", "{client_key}").Methods("GET")

	router.HandleFunc("/api/v1/report_bad_ip/{ip}/{reason}", func(w http.ResponseWriter, r *http.Request) {
		reportBadIPHandler(w, r, ipRepLogger)
	}).Methods("POST")

	router.HandleFunc("/api/v1/remove/{phone}", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clientKey := vars["client_key"]

		if clientID, clientExists := clientsK2IMap[clientKey]; clientExists {
			log.Println("Processing request for the client " + clientID)
			removalHandler(w, r, hitsLogs[clientID])
		} else {
			oData := outputData{
				Code:        403,
				Status:      "error",
				Description: "Wrong key provided",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oData)
		}
	}).Queries("client_key", "{client_key}").Methods("DELETE")

	router.HandleFunc("/api/v1/control/inspect", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clientKey := vars["client_key"]

		if clientID, clientExists := clientsK2IMap[clientKey]; clientExists {
			log.Println("Processing request for the client " + clientID)
			inspectHandler(w, r, hitsLogs[clientID])
		} else {
			oData := outputData{
				Code:        403,
				Status:      "error",
				Description: "Wrong key provided",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oData)
		}
	}).Queries("client_key", "{client_key}").Methods("GET")

	router.HandleFunc("/api/v1/control/cleanup", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		clientKey := vars["client_key"]

		if clientID, clientExists := clientsK2IMap[clientKey]; clientExists {
			log.Println("Processing request for the client " + clientID)
			cleanupHandler(w, r, hitsLogs[clientID])
		} else {
			oData := outputData{
				Code:        403,
				Status:      "error",
				Description: "Wrong key provided",
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(oData)
		}
	}).Queries("client_key", "{client_key}").Methods("POST")

	router.NotFoundHandler = http.HandlerFunc(notFoundHandler)

	log.Println("Operations started.")

	log.Fatal(http.ListenAndServe(":8080", router))
}
