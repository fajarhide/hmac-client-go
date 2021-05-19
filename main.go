package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

	config "github.com/joho/godotenv"
)

func main() {
	err := config.Load(".env")
	if err != nil {
		log.Fatal("Error loading .env file")
		os.Exit(2)
	}

	// define variable
	algorithm := fmt.Sprintf("%s", os.Getenv("ALGORITHM"))
	username := fmt.Sprintf("%s", os.Getenv("USERNAME"))
	secret := fmt.Sprintf("%s", os.Getenv("SECRET"))
	url := fmt.Sprintf("%s", os.Getenv("URL"))
	path := fmt.Sprintf("%s", os.Getenv("ENDPOINT"))
	method := fmt.Sprintf("%s", os.Getenv("METHOD"))

	//request path
	url = url + path

	//date
	loc, _ := time.LoadLocation("GMT")
	date := time.Now().In(loc)
	layout := "Mon, 02 Jan 2006 15:04:05 GMT"
	dateFormat := date.Format(layout)

	//body
	data := fmt.Sprintf("%s", os.Getenv("PAYLOAD"))
	requestBody := []byte(data)
	digestBody := sha256.New()
	digestBody.Write([]byte(requestBody))
	digestBodyContent := base64.StdEncoding.EncodeToString(digestBody.Sum(nil))
	digestBodyHeader := "SHA-256=" + digestBodyContent

	//signature
	signingString := "date: " + dateFormat + "\n" + method + " " + path + " HTTP/1.1" + "\n" + "digest: " + digestBodyHeader
	log.Println("signing", signingString)
	digest := hmac.New(sha256.New, []byte(secret))
	digest.Write([]byte(signingString))
	signature := base64.StdEncoding.EncodeToString(digest.Sum(nil))
	log.Println("Signature :", signature)

	client := &http.Client{}
	request, err := http.NewRequest(method, url, bytes.NewBuffer(requestBody))
	if err != nil {
		log.Fatalln(err)
	}

	//header
	authorization := "hmac username=\"" + username + "\", algorithm=\"" + algorithm + "\", headers=\"date request-line digest\", signature=\"" + signature + "\""
	log.Println("Oka-Authorization :", authorization)
	request.Header.Set("Digest", digestBodyHeader)
	request.Header.Set("Oka-Authorization", authorization)
	request.Header.Set("Date", dateFormat)

	resp, err := client.Do(request)
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatalln(err)
	}
	log.Println("response", string(body))

}
