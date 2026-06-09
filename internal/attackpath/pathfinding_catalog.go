package attackpath

import (
	_ "embed"
	"encoding/json"
	"sort"
	"sync"
)

//go:embed pathfinding_catalog.json
var pathfindingCatalogJSON []byte

var (
	pathfindingCatalogOnce    sync.Once
	pathfindingCatalogEntries []pathfindingCatalogEntry
)

type pathfindingCatalogEntry struct {
	ID                string   `json:"id"`
	Name              string   `json:"name"`
	Category          string   `json:"category"`
	Services          []string `json:"services"`
	RequiredActions   []string `json:"required_actions"`
	AdditionalActions []string `json:"additional_actions"`
	References        []string `json:"references"`
	SourcePath        string   `json:"source_path"`
}

func pathfindingCatalog() []pathfindingCatalogEntry {
	pathfindingCatalogOnce.Do(func() {
		var entries []pathfindingCatalogEntry
		if err := json.Unmarshal(pathfindingCatalogJSON, &entries); err != nil {
			return
		}
		sort.SliceStable(entries, func(i int, j int) bool {
			return entries[i].ID < entries[j].ID
		})
		pathfindingCatalogEntries = entries
	})
	return pathfindingCatalogEntries
}

// PathfindingCatalogCoverage returns the embedded pathfinding.cloud catalog size.
func PathfindingCatalogCoverage() int {
	return len(pathfindingCatalog())
}
