package main

import (
	"crypto/sha256"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/antonholmquist/jason"
)

// 1445f8dc16bf7f0e1c7b3d16bee14ef83e6170ab00a2381d509051c64617fbfd / proquota.exe
func determineFileSHA256(file string) []byte {
	f, err := os.Open(file)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("%x", h.Sum(nil))
	return h.Sum(nil)
}

func SHA256Scan(sha256 string) {

	apikey := os.Getenv("VTAPIKEY")

	url := "https://www.virustotal.com/api/v3/files/" + sha256

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey)

	res, _ := http.DefaultClient.Do(req)

	v, _ := jason.NewObjectFromReader(res.Body)

	threatLabel, _ := v.GetString("data", "attributes", "popular_threat_classification", "suggested_threat_label")

	malCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "malicious")
	susCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "suspicious")
	undetectedCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "undetected")
	harmlessCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "harmless")
	timeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "timeout")
	confirmedtimeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "confirmed-timeout")
	failureCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "failure")
	unsupportCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "type-unsupported")
	repCat, _ := v.GetInt64("data", "attributes", "reputation")

	fmt.Println("\nThreat Label: ", threatLabel)
	fmt.Println("____________________________________")
	fmt.Println("\nMalicious: ", malCat)
	fmt.Println("Suspicious: ", susCat)
	fmt.Println("Undetected: ", undetectedCat)
	fmt.Println("Harmless: ", harmlessCat)
	fmt.Println("Timeout: ", timeoutCat)
	fmt.Println("Confirmed Timeout: ", confirmedtimeoutCat)
	fmt.Println("Failure: ", failureCat)
	fmt.Println("Unsupported: ", unsupportCat)
	fmt.Println("____________________________________")

	fmt.Println("\nReputation: ", repCat)

	defer res.Body.Close()
}

func fileScan(sha256 string) {

	apikey := os.Getenv("VTAPIKEY")

	url := "https://www.virustotal.com/api/v3/files/" + sha256

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("accept", "application/json")
	req.Header.Add("x-apikey", apikey)

	res, _ := http.DefaultClient.Do(req)

	v, _ := jason.NewObjectFromReader(res.Body)

	threatLabel, _ := v.GetString("data", "attributes", "popular_threat_classification", "suggested_threat_label")

	malCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "malicious")
	susCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "suspicious")
	undetectedCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "undetected")
	harmlessCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "harmless")
	timeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "timeout")
	confirmedtimeoutCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "confirmed-timeout")
	failureCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "failure")
	unsupportCat, _ := v.GetInt64("data", "attributes", "last_analysis_stats", "type-unsupported")
	repCat, _ := v.GetInt64("data", "attributes", "reputation")

	fmt.Println("\nThreat Label: ", threatLabel)
	fmt.Println("____________________________________")
	fmt.Println("\nMalicious: ", malCat)
	fmt.Println("Suspicious: ", susCat)
	fmt.Println("Undetected: ", undetectedCat)
	fmt.Println("Harmless: ", harmlessCat)
	fmt.Println("Timeout: ", timeoutCat)
	fmt.Println("Confirmed Timeout: ", confirmedtimeoutCat)
	fmt.Println("Failure: ", failureCat)
	fmt.Println("Unsupported: ", unsupportCat)
	fmt.Println("____________________________________")

	fmt.Println("\nReputation: ", repCat)

	defer res.Body.Close()
}

func main() {
	var sha256Flag = flag.String("sha256", "", "SHA256 to check")
	var fileFlag = flag.String("file", "", "File to check")

	flag.Parse()

	sha256F := *sha256Flag
	fileF := *fileFlag

	if sha256F != "" {
		SHA256Scan(sha256F)
	} else if fileF != "" {
		fileSHA256 := determineFileSHA256(fileF)
		fileScan(string(fileSHA256))
	} else {
		var i string
		fmt.Print("\nSHA256 of Sample: ")
		fmt.Scan(&i)
		SHA256Scan(i)
	}
}
