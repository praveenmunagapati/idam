package file

import (
	"encoding/json"
	"os"
)

func writeFile(f string, payload interface{}) error {
	fd, err := os.Create(f)
	if err != nil {
		return nil
	}
	defer fd.Close()

	encoder := json.NewEncoder(fd)

	encoder.SetIndent("", "  ")

	return encoder.Encode(payload)
}

func readFile(f string, payload interface{}) error {
	fd, err := os.Open(f)
	if err != nil {
		return err
	}
	defer fd.Close()

	decoder := json.NewDecoder(fd)

	return decoder.Decode(payload)
}
