package main

import (
	"io"
	"net/http"
	"strings"
)

func loadList() map[string]string {
	resp, err := http.Get("https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts")
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	rawlines := strings.Split(string(raw), "\n")

	blockList := make(map[string]string) // map of ips indexable by domain name
	for _, line := range rawlines {
		parts := strings.Split(line, " ")
		if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" || len(parts) < 2 {
			continue
		}

		// add to blocklist
		blockList[parts[1]+"."] = parts[0]

	}

	//log.Println(blockList)
	return blockList
}
