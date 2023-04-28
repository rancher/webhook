package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"
)

// docFileName defines the name of the files that will be aggregated into overall docs
const docFileExtension = ".md"

type docFile struct {
	content  []byte
	resource string
	group    string
	version  string
}

func generateDocs(resourcesBaseDir, outputFilePath string) error {
	outputFile, err := os.OpenFile(outputFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	if err != nil {
		return err
	}
	docFiles, err := getDocFiles(resourcesBaseDir)
	if err != nil {
		return fmt.Errorf("unable to create documentation: %w", err)
	}
	currentGroup := ""
	for _, docFile := range docFiles {
		newGroup := docFile.group
		if newGroup != currentGroup {
			// our group has changed, output a new group header
			_, err = fmt.Fprintf(outputFile, "# %s/%s \n \n", docFile.group, docFile.version)
			if err != nil {
				return fmt.Errorf("unable to write group header for %s/%s: %w", docFile.group, docFile.version, err)
			}
			currentGroup = newGroup
		}

		_, err = fmt.Fprintf(outputFile, "## %s \n\n", docFile.resource)
		if err != nil {
			return fmt.Errorf("unable to write resource header for %s: %w", docFile.resource, err)
		}

		lines := strings.Split(string(docFile.content), "\n")
		for i, line := range lines {
			newLine := line
			if i < len(lines)-1 {
				// last line doesn't need a newLine re-added
				newLine += "\n"
			}
			if strings.HasPrefix(line, "#") {
				// this line is a markdown header. Since the group header is the top-level indent, indent this down one line
				newLine = "#" + line
			}
			_, err := outputFile.WriteString(newLine)
			if err != nil {
				return fmt.Errorf("unable to write content for %s/%s.%s: %w", docFile.group, docFile.version, docFile.resource, err)
			}
		}
	}
	return nil
}

// getDocFiles finds all markdown files recursively in resourcesBaseDir and converts them to docFiles. Returns in a sorted order,
// first by group, then by resourceName
func getDocFiles(baseDir string) ([]docFile, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return nil, fmt.Errorf("unable to list entries in directory %s: %w", baseDir, err)
	}
	var docFiles []docFile
	for _, entry := range entries {
		entryPath := filepath.Join(baseDir, entry.Name())
		if entry.IsDir() {
			subDocFiles, err := getDocFiles(entryPath)
			if err != nil {
				return nil, err
			}
			docFiles = append(docFiles, subDocFiles...)
		}
		if filepath.Ext(entry.Name()) == docFileExtension {
			content, err := os.ReadFile(filepath.Join(baseDir, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("unable to read file content for %s: %w", entryPath, err)
			}
			var newDir, resource, version, group string
			newDir, _ = filepath.Split(baseDir)
			newDir, version = filepath.Split(newDir[:len(newDir)-1])
			newDir, group = filepath.Split(newDir[:len(newDir)-1])
			resource = strings.TrimSuffix(entry.Name(), docFileExtension)
			if newDir == "" || resource == "" || version == "" || group == "" {
				return nil, fmt.Errorf("unable to extract gvr from %s, got group %s, version %s, resource %s", baseDir, group, version, resource)
			}
			docFiles = append(docFiles, docFile{
				content:  content,
				resource: resource,
				group:    group,
				version:  version,
			})
		}
	}
	// if the groups differ, sort based on the group. If the groups are the same, sort based on the resource
	slices.SortFunc(docFiles, func(a, b docFile) bool {
		if a.group < b.group {
			return true
		} else if a.group == b.group {
			return a.resource < b.resource
		}
		return false
	})

	return docFiles, nil
}
