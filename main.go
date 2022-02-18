package main

import (
	"bufio"
	"encoding/csv"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

func main() {

	flagSrc := flag.String("path", "", "Source Path")
	flagDest := flag.String("dest", "", "Dest Path")

	flag.Parse()
	pathName := *flagSrc

	pathDest := *flagDest

	if pathName == "" {
		log.Fatalf("No Source Path")
	}

	if pathDest == "" {
		pathDest = pathName
	}

	pathName = strings.Replace(pathName, `\`, `/`, -1) // This will need to be changed if deployed on nix

	files, err := ioutil.ReadDir(pathName)
	if err != nil {
		log.Fatalf(`Error %s`, err.Error())
	}

	var wg sync.WaitGroup
	for _, f := range files {
		if !strings.Contains(strings.ToLower(f.Name()), ".rar") && !strings.Contains(strings.ToLower(f.Name()), ".zip") && !strings.Contains(strings.ToLower(f.Name()), ".csv") && (strings.Contains(strings.ToLower(f.Name()), ".log") || strings.Contains(strings.ToLower(f.Name()), ".txt")) {
			wg.Add(1)
			go process(f, pathName, pathDest, &wg)
		}

	}
	wg.Wait()

}
func process(fl os.FileInfo, pathName, pathDest string, wg *sync.WaitGroup) {
	defer wg.Done()
	f, err := os.Open(filepath.Join(pathName, fl.Name()))
	if err != nil {
		log.Fatal()
	}

	defer f.Close()

	start := time.Now()

	scanner := bufio.NewScanner(f)

	it := 1
	dataStartType1 := false
	dataCommandType1 := "dis arp all"
	dataSeperatorType1 := "----------------------------------"

	dataStartType2 := false
	dataCommandType2 := "dis int desc"
	dataSeperatorType2 := "Interface"

	routerName := ""

	rowType1 := [][]string{}
	headerType1 := []string{"Router", "IP Address", "MAC Address", "Expire(M)", "Type VLAN/CEVLAN", "Interface PVC", "VPN-Instance"}

	rowType2 := [][]string{}
	headerType2 := []string{"Router", "Interface", "PHY", "Protocol", "Description"}

	rowType1 = append(rowType1, headerType1)
	rowType2 = append(rowType2, headerType2)

	for scanner.Scan() {
		it++
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		if strings.Contains(line, dataSeperatorType1) && !dataStartType1 {
			dataStartType1 = true
			continue
		}

		if dataStartType1 && strings.Contains(line, dataSeperatorType1) || (dataStartType1 && strings.Contains(line, "closed.")) || (dataStartType1 && strings.Contains(strings.ToLower(line), "broken")) {
			dataStartType1 = false
			continue
		}

		if len(line) >= len(dataSeperatorType2) && line[0:len(dataSeperatorType2)] == dataSeperatorType2 {
			dataStartType2 = true
			continue
		}

		if (dataStartType2 && strings.Contains(line, ">")) || (dataStartType2 && strings.Contains(strings.ToLower(line), "closed.")) || (dataStartType2 && strings.Contains(strings.ToLower(line), "broken")) {
			dataStartType2 = false
			continue
		}

		if !dataStartType1 {
			if strings.Contains(line, dataCommandType1) {
				routerName = line[strings.Index(line, "<")+1 : strings.Index(line, ">")]
			}
		}

		if !dataStartType2 {
			if strings.Contains(line, dataCommandType2) {
				routerName = line[strings.Index(line, "<")+1 : strings.Index(line, ">")]
			}
		}

		if dataStartType2 {
			dataRow := strings.Fields(line)
			tmpRow := [5]string{}
			tmpRow[0] = routerName

			if strings.Contains(strings.ToLower(dataRow[1]), "up") || strings.Contains(strings.ToLower(dataRow[1]), "down") {
				// No Space in First Field
				tmpRow[1] = dataRow[0]
				tmpRow[2] = dataRow[1]
				tmpRow[3] = dataRow[2]
				lastVal := strings.Join(dataRow[3:], " ")
				tmpRow[4] = lastVal
			} else {
				tmpRow[1] = strings.Join(dataRow[0:2], " ")
				tmpRow[2] = dataRow[2]
				tmpRow[3] = dataRow[3]
				lastVal := strings.Join(dataRow[4:], " ")
				tmpRow[4] = lastVal

			}

			rowType2 = append(rowType2, tmpRow[:])

		}

		if dataStartType1 {

			dataRow := strings.Fields(strings.TrimSpace(line))

			tmpRow := [7]string{}
			tmpRow[0] = routerName
			numberOfSplit := len(dataRow)

			if numberOfSplit == 1 {
				// This Will Append Only for Type
				rowType1[len(rowType1)-1][4] = rowType1[len(rowType1)-1][4] + " " + strings.TrimSpace(dataRow[0])
				continue
			}

			lastIndex := 0 // This will be used after TYPE field has been assigned

			for i := numberOfSplit - 1; i >= 0; i-- { // Iterate backwards for the last 2 Field
				fieldValue := strings.TrimSpace(dataRow[i])
				lastField := strings.TrimSpace(dataRow[numberOfSplit-1])

				// Check Last Field for INTERFACE field if it contains "/" or "eth" or "vlan" and if NOT assign value to VPN-INSTANCE
				if lastField == fieldValue {
					if strings.Contains(strings.ToLower(fieldValue), "/") ||
						strings.Contains(strings.ToLower(fieldValue), "eth") ||
						strings.Contains(strings.ToLower(fieldValue), "vlan") {
						tmpRow[5] = fieldValue
						getShortestIndex(&lastIndex, strings.Index(line, fieldValue))

					} else {
						tmpRow[6] = fieldValue
						getShortestIndex(&lastIndex, strings.Index(line, fieldValue))

					}
				}

				// After Last Field Check for INTERFACE
				if strings.Contains(strings.ToLower(fieldValue), "/") ||
					strings.Contains(strings.ToLower(fieldValue), "eth") ||
					strings.Contains(strings.ToLower(fieldValue), "vlan") {
					tmpRow[5] = fieldValue
					getShortestIndex(&lastIndex, strings.Index(line, fieldValue))

				}

				// Exit if TYPE has been assigned
				if tmpRow[5] != "" {
					break
				}

			}

			// Get Help from Regex for TYPE FIELD AFTER MAC ADDRESS
			r := regexp.MustCompile(`((D|I|S|O|R)( |-|\/){0,2}).*`)
			stringCheck := line[strings.Index(line, strings.TrimSpace(dataRow[1]))+len(strings.TrimSpace(dataRow[1])) : lastIndex]
			matches := r.FindAllString(stringCheck, -1)

			tmpRow[4] = strings.TrimSpace(matches[0])

			// Assign 1st and 2nd Value to IP ADDRESS and MAC ADDRESS
			tmpRow[1] = strings.TrimSpace(dataRow[0])
			tmpRow[2] = strings.TrimSpace(dataRow[1])

			// Get Expire TIME --> EXPECTED TO BE INT
			exp, err := strconv.Atoi(strings.TrimSpace(dataRow[2]))
			if err == nil {
				tmpRow[3] = fmt.Sprintf("%v", exp)
			}

			rowType1 = append(rowType1, tmpRow[:])

		}

	}

	baseName := fileNameWithoutExtSliceNotation(f.Name())
	baseName = filepath.Base(baseName)

	if len(rowType1) > 1 {

		newFileName := filepath.Join(pathDest, baseName+"_"+dataCommandType1+".csv")

		file, err := os.Create(newFileName)

		if err != nil {
			log.Fatalln(err)
		}

		defer file.Close()

		csvWriter := csv.NewWriter(file)
		csvWriter.WriteAll(rowType1)
		csvWriter.Flush()
	}

	if len(rowType2) > 1 {
		newFileName := filepath.Join(pathDest, baseName+"_"+dataCommandType2+".csv")

		file, err := os.Create(newFileName)

		if err != nil {
			log.Fatalln(err)
		}

		defer file.Close()

		csvWriter := csv.NewWriter(file)
		csvWriter.WriteAll(rowType2)
		csvWriter.Flush()
	}

	log.Printf("%s took %v\n", baseName, time.Since(start))

}

func getShortestIndex(lastIndex *int, currentIndex int) {
	if *lastIndex == 0 {
		*lastIndex = currentIndex
	} else if *lastIndex >= currentIndex {
		*lastIndex = currentIndex
	}

}

func fileNameWithoutExtSliceNotation(fileName string) string {
	return fileName[:len(fileName)-len(filepath.Ext(fileName))]
}
