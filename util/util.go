package util

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"time"

	"golang.org/x/crypto/sha3"
)

func GetBytesFromFile(filename string) (bytes []byte, err error) {
	data, err := ioutil.ReadFile(filename)
	bytes = []byte(data)
	return
}

func GenereBytes(lengtn int) (bytes []byte) {
	seed := uniform(128)
	bytes = shake(seed, lengtn)
	return
}

func SetArrMapToFile(data []map[int]map[uint16]float64, filename string) {
	jsonString, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile(filename, jsonString, 0644)
}

func SetMapToFile(data map[int]map[uint16]float64, filename string) {
	jsonString, _ := json.MarshalIndent(data, "", " ")
	_ = ioutil.WriteFile(filename, jsonString, 0644)
}

func SetStringToFile(bytes []byte, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	l, err := file.WriteString(string(bytes))
	if err != nil {
		return err
	}
	fmt.Printf("%d-len string has written successfully\n", l)
	err = file.Close()
	if err != nil {
		return err
	}
	return nil
}

func uniform(length int) []byte {
	temp := make([]byte, length)
	rand.Seed(time.Now().UTC().UnixNano())
	for i := range temp {
		temp[i] = byte(rand.Intn(256))
	}
	return temp
}

func shake(write []byte, length int) []byte {
	read := make([]byte, length)
	shake := sha3.NewShake128()
	shake.Write(write)
	shake.Read(read)
	return read
}
