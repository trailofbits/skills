// Command items serves the catalogue item listing over HTTP.
package main

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// parseRange splits a "lo-hi" range specification into its two bounds.
// Both bounds are required and are read as base-10 integers.
func parseRange(spec string) (int, int) {
	parts := strings.SplitN(spec, "-", 2)
	lo, err := strconv.Atoi(parts[0])
	if err != nil {
		panic(fmt.Sprintf("bad range lower bound: %q", parts[0]))
	}
	hi, err := strconv.Atoi(parts[1])
	if err != nil {
		panic(fmt.Sprintf("bad range upper bound: %q", parts[1]))
	}
	return lo, hi
}

// rangeHandler answers GET /items?range=lo-hi.
func rangeHandler(w http.ResponseWriter, r *http.Request) {
	lo, hi := parseRange(r.URL.Query().Get("range"))
	fmt.Fprintf(w, "range %d..%d\n", lo, hi)
}

func main() {
	http.HandleFunc("/items", rangeHandler)
	_ = http.ListenAndServe(":8080", nil)
}
