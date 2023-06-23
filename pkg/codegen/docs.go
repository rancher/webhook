package main

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/exp/slices"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// docFileName defines the name of the files that will be aggregated into overall docs
const docFileExtension = ".md"

type docFile struct {
	content  []byte
	resource string
	group    string
	version  string
}

func generateDocs(resourcesBaseDir, outputFilePath string) (err error) {
	outputFile, err := os.OpenFile(outputFilePath, os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0666)
	defer func() {
		closeErr := outputFile.Close()
		if closeErr != nil {
			if err != nil {
				err = fmt.Errorf("%w, error when closing file %s", err, closeErr.Error())
			} else {
				err = closeErr
			}
		}
	}()
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
			groupFormatString := "# %s/%s \n"
			if currentGroup != "" {
				groupFormatString = "\n" + groupFormatString
			}
			_, err = fmt.Fprintf(outputFile, groupFormatString, docFile.group, docFile.version)
			if err != nil {
				return fmt.Errorf("unable to write group header for %s/%s: %w", docFile.group, docFile.version, err)
			}
			currentGroup = newGroup
		}

		_, err = fmt.Fprintf(outputFile, "\n## %s \n\n", docFile.resource)
		if err != nil {
			return fmt.Errorf("unable to write resource header for %s: %w", docFile.resource, err)
		}
		scanner := bufio.NewScanner(bytes.NewReader(docFile.content))
		for scanner.Scan() {
			line := scanner.Bytes()
			// even if the scanned line is empty, still need to output the newline
			if len(line) != 0 && line[0] == '#' {
				// this line is a markdown header. Since the group header is the top-level indent, indent this down one line
				line = append([]byte{'#'}, line...)
			}
			line = append(line, byte('\n'))
			_, err := outputFile.Write(line)
			if err != nil {
				return fmt.Errorf("unable to write content for %s/%s.%s: %w", docFile.group, docFile.version, docFile.resource, err)
			}
		}
		if scanner.Err() != nil {
			return fmt.Errorf("got an error scanning content for %s/%s.%s: %w", docFile.group, docFile.version, docFile.resource, err)
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
			continue
		}
		if filepath.Ext(entry.Name()) != docFileExtension {
			continue
		}
		content, err := os.ReadFile(filepath.Join(baseDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("unable to read file content for %s: %w", entryPath, err)
		}
		// lop off the last trailing new line to keep consistent spacing for later on
		if content[len(content)-1] == '\n' {
			content = content[:len(content)-1]
		}
		newDir, _ := filepath.Split(baseDir)
		newDir, version := filepath.Split(newDir[:len(newDir)-1])
		newDir, group := filepath.Split(newDir[:len(newDir)-1])
		resource := strings.TrimSuffix(entry.Name(), docFileExtension)
		if newDir == "" || resource == "" || version == "" || group == "" {
			return nil, fmt.Errorf("unable to extract gvr from %s, got group %s, version %s, resource %s", baseDir, group, version, resource)
		}
		// group and version need to have a consistent case so that test.cattle.io/v3 and test.cattle.Io/V3 are grouped the same way
		caser := cases.Lower(language.English)
		docFiles = append(docFiles, docFile{
			content:  content,
			resource: resource,
			group:    caser.String(group),
			version:  caser.String(version),
		})
	}
	// if the groups differ, sort based on the group. If the groups are the same, sort based on the resource
	slices.SortFunc(docFiles, func(a, b docFile) bool {
		if a.group == b.group {
			if a.resource == b.resource {
				return a.version < b.version
			}
			return a.resource == b.resource
		}
		return a.group < b.group
	})

	return docFiles, nil
}
