// Author: Ori Talmor
// Student Number: 0978566
// Email: otalmor@uoguelph.ca
// Course: CIS*6580 Security Monitoring and Threat Hunting
//
// Description: This program reads a CSV file containing email records, splits the data into training and learning sets,
// converts the records to JSON format, and writes the output to separate JSON files. The training set consists of 30
// randomly selected records, while the learning set contains the remaining records.

package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"os"
	"time"
)

// EmailRecord defines the structure of the JSON output
type EmailRecord struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Result bool   `json:"phish"`
}

// TrainingEmailRecord defines the structure for the training data file with id and email
type TrainingEmailRecord struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// TrainingResultRecord defines the structure for the training data file with id and result
type TrainingResultRecord struct {
	ID     string `json:"id"`
	Result bool   `json:"phish"`
}

// ReadCSV reads the CSV file and returns a slice of EmailRecord
func ReadCSV(filename string) (records []EmailRecord, err error) {
	csvFile, readErr := os.Open(filename)
	if readErr != nil {
		return nil, fmt.Errorf("unable to open csv file for reading: %v", readErr)
	}
	defer csvFile.Close()

	csvReader := csv.NewReader(csvFile)

	_, headerLineErr := csvReader.Read()
	if headerLineErr != nil {
		return nil, fmt.Errorf("unable to read csv header: %v", headerLineErr)
	}

	for {
		record, recordReadErr := csvReader.Read()
		if recordReadErr != nil {
			if recordReadErr == csv.ErrFieldCount {
				return nil, fmt.Errorf("error reading csv record: %v", recordReadErr)
			}
			break
		}

		emailRecord := EmailRecord{
			ID:     record[0],
			Email:  record[1],
			Result: record[2] == "Phishing Email",
		}

		records = append(records, emailRecord)
	}

	return records, nil
}

// ConvertToJSON converts a slice of any data type to a JSON byte array
func ConvertToJSON(data interface{}) (jsonData []byte, err error) {
	jsonData, jsonMarshalErr := json.MarshalIndent(data, "", "  ")
	if jsonMarshalErr != nil {
		return nil, fmt.Errorf("unable to marshal json data: %v", jsonMarshalErr)
	}
	return jsonData, nil
}

// WriteJSON writes the JSON byte array to a file
func WriteJSON(filename string, data []byte) (err error) {
	fileWriteErr := os.WriteFile(filename, data, 0644)
	if fileWriteErr != nil {
		return fmt.Errorf("unable to write json to file: %v", fileWriteErr)
	}
	return nil
}

// SplitAndWriteJSON splits the JSON data into multiple files with a maximum size limit, ensuring JSON objects are not split
func SplitAndWriteJSON(fileNamePrefix string, records []EmailRecord, maxSizeKB int) (err error) {
	const bytesPerKB = 1024
	maxSize := maxSizeKB * bytesPerKB

	chunkNum := 1
	startIdx := 0

	for startIdx < len(records) {
		endIdx := startIdx
		var chunkData []byte
		var err error

		// Try to fit as many records as possible into one part without exceeding maxSize
		for endIdx < len(records) {
			chunkData, err = json.MarshalIndent(records[startIdx:endIdx+1], "", "  ")
			if err != nil {
				return fmt.Errorf("unable to marshal json data: %v", err)
			}
			if len(chunkData) > maxSize {
				break
			}
			endIdx++
		}

		// If we can't even fit one record, we must write it anyways
		if startIdx == endIdx {
			endIdx++
		}

		chunkData, err = json.MarshalIndent(records[startIdx:endIdx], "", "  ")
		if err != nil {
			return fmt.Errorf("unable to marshal json data into final form: %v", err)
		}

		chunkName := fmt.Sprintf("%s_%d.json", fileNamePrefix, chunkNum)
		if fileWriteErr := WriteJSON(chunkName, chunkData); fileWriteErr != nil {
			return fmt.Errorf("unable to write json chunk %s: %v", chunkName, fileWriteErr)
		}

		chunkNum++
		startIdx = endIdx
	}

	return nil
}

// SplitData splits the records into training and learning sets
func SplitData(records []EmailRecord, trainCount, testCount int) (trainSet, testSet, learnSet []EmailRecord, err error) {
	prng := rand.New(rand.NewSource(time.Now().UnixNano()))

	totalCount := len(records)
	if trainCount+testCount >= totalCount {
		return nil, nil, nil, fmt.Errorf("training count (%d) and ttesting count (%d) is greater than or equal to the total records (%d)", trainCount, testCount, totalCount)
	}

	// Generate random indicies for the training and testing sets
	randomIndices := prng.Perm(totalCount)
	trainIndices := randomIndices[:trainCount]
	testIndices := randomIndices[trainCount : trainCount+testCount]

	trainSet = make([]EmailRecord, 0, trainCount)
	testSet = make([]EmailRecord, 0, testCount)
	learnSet = make([]EmailRecord, 0, totalCount-trainCount-testCount)

	for i, record := range records {
		if contains(trainIndices, i) {
			trainSet = append(trainSet, record)
		} else if contains(testIndices, i) {
			testSet = append(testSet, record)
		} else {
			learnSet = append(learnSet, record)
		}
	}

	return trainSet, testSet, learnSet, nil
}

// contains checks if a slice contains a specific integer
func contains(slice []int, i int) bool {
	for _, v := range slice {
		if v == i {
			return true
		}
	}

	return false
}

func main() {
	csvFileName := "Phishing_Email.csv"
	trainEmailJSONFileName := "Phishing_Training_Data.json"
	trainResultJSONFileName := "Phishing_Training_Result.json"
	testJSONFileName := "Phishing_Testing_Data.json"
	learnJSONFilePrefix := "Phishing_Learning_Data"
	trainCount := 30
	testCount := 20
	maxFileSizeKB := 5000 //5Mb

	// Step 1: Read CSV file
	records, readCSVErr := ReadCSV(csvFileName)
	if readCSVErr != nil {
		log.Fatalf("Error reading csv file: %v", readCSVErr)
	}

	// Step 2: Split data into training, testing and learning sets
	trainSet, testSet, learnSet, splitErr := SplitData(records, trainCount, testCount)
	if splitErr != nil {
		log.Fatalf("Error splitting data into learning and training sets: %v", splitErr)
	}

	// Step 3: Prepare training data with emails
	var trainEmailSet []TrainingEmailRecord
	for _, record := range trainSet {
		trainEmailSet = append(trainEmailSet, TrainingEmailRecord{ID: record.ID, Email: record.Email})
	}

	// Step 4: Prepare training data with results
	var trainResultSet []TrainingResultRecord
	for _, record := range trainSet {
		trainResultSet = append(trainResultSet, TrainingResultRecord{ID: record.ID, Result: record.Result})
	}

	// Step 5: Convert training data to JSON
	trainEmailJsonData, convertTrainEmailJSONErr := ConvertToJSON(trainEmailSet)
	if convertTrainEmailJSONErr != nil {
		log.Fatalf("Error converting training email data to JSON: %v", convertTrainEmailJSONErr)
	}

	trainResultJsonData, convertTrainResultJSONErr := ConvertToJSON(trainResultSet)
	if convertTrainResultJSONErr != nil {
		log.Fatalf("Error converting training result data to JSON: %v", convertTrainResultJSONErr)
	}

	// Step 6: Write training set JSON to file
	if trainEmailJSONWriteErr := WriteJSON(trainEmailJSONFileName, trainEmailJsonData); trainEmailJSONWriteErr != nil {
		log.Fatalf("Error writing training email JSON file: %v", trainEmailJSONWriteErr)
	}

	if trainResultJSONWriteErr := WriteJSON(trainResultJSONFileName, trainResultJsonData); trainResultJSONWriteErr != nil {
		log.Fatalf("Error writing training result JSON file: %v", trainResultJSONWriteErr)
	}

	// Step 7: Convert testing data to JSON
	testJSONData, convertTestJsonErr := ConvertToJSON(testSet)
	if convertTestJsonErr != nil {
		log.Fatalf("Error converting testing data to JSON: %v", convertTestJsonErr)
	}

	// Step 8:Write testing set JSON to file
	if testJSONWriteErr := WriteJSON(testJSONFileName, testJSONData); testJSONWriteErr != nil {
		log.Fatalf("Error writing testing JSON file: %v", testJSONWriteErr)
	}

	// Step 7: Split and write learning set to multiple files in JSON based on chunk size
	if learnJSONWriteErr := SplitAndWriteJSON(learnJSONFilePrefix, learnSet, maxFileSizeKB); learnJSONWriteErr != nil {
		log.Fatalf("Error writing learning JSON file: %v", learnJSONWriteErr)
	}

	fmt.Printf("CSV data from %s has been converted to JSON and split into:\n  - training data, %d records (%s and %s)\n  - learning data (%s_*.json)\n", csvFileName, trainCount, trainEmailJSONFileName, trainResultJSONFileName, learnJSONFilePrefix)
}
