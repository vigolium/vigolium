package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"github.com/vigolium/vigolium/pkg/storage"
	"github.com/vigolium/vigolium/pkg/terminal"
)

var storageLsCmd = &cobra.Command{
	Use:     "ls",
	Aliases: []string{"list"},
	Short:   "List objects in cloud storage for the active project",
	Long:    "List objects under the active project's prefix in the configured bucket. Use --prefix to scope to a sub-path (e.g. ugc/ or native-scans/). Use --tree to render the keys as a directory tree.",
	RunE:    runStorageLs,
}

func init() {
	storageLsCmd.Flags().String("prefix", "", "Limit results to keys under this prefix")
	storageLsCmd.Flags().Bool("json", false, "Output as JSON")
	storageLsCmd.Flags().Bool("tree", false, "Render objects as a directory tree")
	storageCmd.AddCommand(storageLsCmd)
}

func runStorageLs(cmd *cobra.Command, _ []string) error {
	defer closeDatabaseOnExit()

	sc, projectUUID, err := openStorageClient()
	if err != nil {
		return err
	}
	if sc == nil {
		return nil
	}

	prefix, _ := cmd.Flags().GetString("prefix")
	jsonOut, _ := cmd.Flags().GetBool("json")
	treeOut, _ := cmd.Flags().GetBool("tree")

	objects, err := sc.List(context.Background(), projectUUID, prefix)
	if err != nil {
		return fmt.Errorf("failed to list storage objects: %w", err)
	}

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if objects == nil {
			return enc.Encode([]struct{}{})
		}
		return enc.Encode(objects)
	}

	if len(objects) == 0 {
		fmt.Printf("%s No objects found for project %s", terminal.InfoSymbol(), terminal.Cyan(projectUUID))
		if prefix != "" {
			fmt.Printf(" under prefix %s", terminal.Gray(prefix))
		}
		fmt.Println()
		return nil
	}

	if treeOut {
		root := buildStorageTree(objects)
		header := terminal.Cyan(projectUUID)
		if prefix != "" {
			header += "/" + terminal.Gray(strings.TrimSuffix(prefix, "/"))
		}
		fmt.Println(header)
		printStorageTree(root, "")
		fmt.Printf("\n%s Total: %d object(s) in project %s\n",
			terminal.InfoSymbol(), len(objects), terminal.Cyan(projectUUID))
		return nil
	}

	tbl := terminal.NewTableWithMaxWidth(globalWidth, "KEY", "SIZE", "MODIFIED", "CONTENT-TYPE")
	for _, obj := range objects {
		ct := obj.ContentType
		if ct == "" {
			ct = "-"
		}
		tbl.AddRow(
			terminal.Cyan(obj.Key),
			humanBytes(obj.Size),
			obj.LastModified.Format("2006-01-02 15:04"),
			terminal.Gray(ct),
		)
	}
	tbl.Print()

	fmt.Printf("\n%s Total: %d object(s) in project %s\n",
		terminal.InfoSymbol(), len(objects), terminal.Cyan(projectUUID))
	return nil
}

// storageTreeNode is a single node in the rendered storage tree. A node can be
// both a directory (children != nil) and a leaf (isLeaf == true), which happens
// when an object key collides with a directory prefix.
type storageTreeNode struct {
	name     string
	children map[string]*storageTreeNode
	isLeaf   bool
	size     int64
}

func buildStorageTree(objects []storage.ObjectInfo) *storageTreeNode {
	root := &storageTreeNode{children: map[string]*storageTreeNode{}}
	for _, obj := range objects {
		parts := strings.Split(obj.Key, "/")
		node := root
		for i, p := range parts {
			if p == "" {
				continue
			}
			child, ok := node.children[p]
			if !ok {
				child = &storageTreeNode{name: p, children: map[string]*storageTreeNode{}}
				node.children[p] = child
			}
			if i == len(parts)-1 {
				child.isLeaf = true
				child.size = obj.Size
			}
			node = child
		}
	}
	return root
}

func printStorageTree(n *storageTreeNode, prefix string) {
	keys := make([]string, 0, len(n.children))
	for k := range n.children {
		keys = append(keys, k)
	}
	// Directories first, then files; alphabetical within each group.
	sort.Slice(keys, func(i, j int) bool {
		ci, cj := n.children[keys[i]], n.children[keys[j]]
		di, dj := len(ci.children) > 0, len(cj.children) > 0
		if di != dj {
			return di
		}
		return keys[i] < keys[j]
	})

	for i, k := range keys {
		c := n.children[k]
		isLast := i == len(keys)-1
		connector := "├── "
		if isLast {
			connector = "└── "
		}
		label := terminal.Cyan(c.name)
		if len(c.children) > 0 {
			label += "/"
		}
		line := prefix + connector + label
		if c.isLeaf {
			line += "  " + terminal.Gray(humanBytes(c.size))
		}
		fmt.Println(line)
		if len(c.children) > 0 {
			childPrefix := prefix + "│   "
			if isLast {
				childPrefix = prefix + "    "
			}
			printStorageTree(c, childPrefix)
		}
	}
}
