/*
 * Copyright 2020 ForgeRock AS
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package trees

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
)

// Node represents a tree node
type Node struct {
	Id     string
	Type   string
	Config []byte
}

// Tree represents an AM Auth Tree
type Tree struct {
	Id     string
	Config []byte
}

// readNodeSet loads all tree nodes contained in the directory
// Assumes the directory structure is `directory/NodeType/node-config.json`
func readNodeSet(nodes []Node, directory string) ([]Node, error) {
	rootEntries, err := ioutil.ReadDir(directory)
	if err != nil {
		return nodes, err
	}
	var b []byte
dirLoop:
	for _, entry := range rootEntries {
		if !entry.IsDir() {
			continue dirLoop
		}
		subdirectory := filepath.Join(directory, entry.Name())
		files, err := ioutil.ReadDir(subdirectory)
		if err != nil {
			return nodes, err
		}

	fileLoop:
		for _, file := range files {
			if !isJSONFile(file) {
				continue fileLoop
			}
			b, err = ioutil.ReadFile(filepath.Join(subdirectory, file.Name()))
			if err != nil {
				return nodes, err
			}
			nodes = append(nodes, Node{Id: nameWithoutExtension(file), Type: entry.Name(), Config: b})
		}
	}
	return nodes, err
}

// ReadNodes reads all the tree nodes in the rootDirectory from file into memory
// Assumes the directory structure is `rootDirectory/(in)dependent/NodeType/node-config.json`
// Only .json files are read
// Independent nodes are returned before dependent nodes
func ReadNodes(rootDirectory string) (nodes []Node, err error) {
	independent := filepath.Join(rootDirectory, "independent")
	dependent := filepath.Join(rootDirectory, "dependent")
	if _, err := os.Stat(independent); err == nil {
		nodes, err = readNodeSet(nodes, independent)
		if err != nil {
			return nodes, err
		}
	}
	if _, err := os.Stat(dependent); err == nil {
		nodes, err = readNodeSet(nodes, dependent)
		if err != nil {
			return nodes, err
		}
	}
	return
}

// ReadTrees reads all the trees in dirname from file into memory
func ReadTrees(dirname string) (trees []Tree, err error) {
	files, err := ioutil.ReadDir(dirname)
	if err != nil {
		return
	}
	var b []byte
	for _, f := range files {
		if !isJSONFile(f) {
			continue
		}
		b, err = ioutil.ReadFile(filepath.Join(dirname, f.Name()))
		if err != nil {
			return
		}
		trees = append(trees, Tree{Id: nameWithoutExtension(f), Config: b})
	}
	return
}

// isJSONFile returns true if the file has a json file extension
func isJSONFile(info os.FileInfo) bool {
	return filepath.Ext(info.Name()) == ".json"
}

// nameWithoutExtension returns the name of the file without the file extension
func nameWithoutExtension(info os.FileInfo) string {
	return strings.TrimSuffix(info.Name(), filepath.Ext(info.Name()))
}
