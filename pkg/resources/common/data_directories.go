package common

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rancher/webhook/pkg/admission"
	admissionv1 "k8s.io/api/admission/v1"
)

// ValidateDataDirectoryFormat ensures that no data directory contains a relative path, environment variables,
// shell expressions, or references to the current or parent directory via use of "./" and "../" respectively.
// dir is the path of the data directory, and name corresponds to a print friendly name for this data directory.
func ValidateDataDirectoryFormat(dir, name string) *admissionv1.AdmissionResponse {
	if dir == "" {
		return admission.ResponseAllowed()
	}
	if !filepath.IsAbs(dir) {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory must be an absolute path", name))
	}
	if strings.ContainsAny(dir, "\"'`*?#~=%$|&;<>{}[]()") {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory cannot contain shell expressions", name))
	}
	if filepath.Clean(dir) != dir {
		return admission.ResponseBadRequest(
			fmt.Sprintf("%s data directory is not clean", name))
	}

	return admission.ResponseAllowed()
}

// ValidateDataDirectoryHierarchy ensures that no directories are equal, and no directories include other directories.
// dataDirs is a map with keys corresponding to print friendly names for these data directories, and values representing
// the specific data directories.
func ValidateDataDirectoryHierarchy(dataDirs map[string]string) *admissionv1.AdmissionResponse {
	paths := make([]struct {
		name string
		path string
	}, 0, len(dataDirs))
	for name, dir := range dataDirs {
		// do not attempt to validate empty directory
		if dir == "" {
			continue
		}
		paths = append(paths, struct {
			name string
			path string
		}{
			name: name,
			path: dir,
		})
	}

	for i := range paths {
		for j := i + 1; j < len(paths); j++ {
			path1 := paths[i]
			path2 := paths[j]

			if path1.path == path2.path {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be equal to %s data directory", path1.name, path2.name))
			}

			// check if paths contain one another, at any depth
			if isNestedDataDirectory(path1.path, path2.path) {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be nested inside %s data directory", path2.name, path1.name))
			}
			if isNestedDataDirectory(path2.path, path1.path) {
				return admission.ResponseBadRequest(
					fmt.Sprintf("%s data directory cannot be nested inside %s data directory", path1.name, path2.name))
			}
		}
	}

	return admission.ResponseAllowed()
}

// isNestedDataDirectory reports whether child is nested inside parent at any depth (e.g. "/a/b" and
// "/a/b/c/d" are both considered nested inside "/a"). Both paths are assumed to already be clean,
// absolute paths, as enforced by ValidateDataDirectoryFormat.
func isNestedDataDirectory(parent, child string) bool {
	return strings.HasPrefix(child, parent+string(filepath.Separator))
}
