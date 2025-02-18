// Copyright 2021 The Witness Contributors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"log"

	"github.com/spf13/cobra/doc"
	"github.com/testifysec/witness/cmd/witness/cmd"
)

var directory string

func init() {
	flag.StringVar(&directory, "dir", "docs", "Directory to store the generated docs")
	flag.Parse()
}

func main() {
	// Generate CLI docs
	if err := doc.GenMarkdownTree(cmd.New(), directory); err != nil {
		log.Fatalf("Error generating docs: %s", err)
	}
}
