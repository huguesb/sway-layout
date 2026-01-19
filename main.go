// Copyright (c) 2026, Hugues Bruant <hugues@betakappaphi.com>
// SPDX-License-Identifier: BSD-3-Clause
//
// sway-layout: Declarative layout builder for Sway
//
// Approach:
//
// The challenge is correlating spawned windows back to their intended position
// in the layout tree. Sway's IPC gives us the PID of a new window, but no way
// to tag it before it appears. Our solution: launch each app via a "spawn"
// wrapper process that encodes workspace and tree-path in its cmdline. When a
// window appears, we walk up /proc/<pid>/stat to find the spawn ancestor and
// extract the placement metadata.
//
// Layout flow:
//   1. Parse config into a tree of containers and app leaves, each with a path
//      (e.g. "0.1.0" = first child's second child's first child)
//   2. Subscribe to window events; immediately move new windows to scratchpad
//      (prevents flicker while we figure out where they go)
//   3. Launch apps via: sway-layout spawn <ws> <path> <cmd>
//   4. For each new window, walk process tree to find spawn wrapper, extract
//      ws+path, record mapping of path -> con_id
//   5. Once all windows are collected (or timeout), arrange each workspace:
//      bring windows out of scratchpad in tree order, using marks and split
//      commands to build the container hierarchy
//
// Config format:
//   {"workspaces": {"1": {"tabbed": ["foot", "firefox", {"splitv": ["htop", "ncdu"]}]}}}
//
// Modes:
//   sway-layout [--force] <config.json>  - Load layout from config
//   sway-layout spawn <ws> <path> cmd... - Spawn wrapper (used internally)
//
// Build: go build -o sway-layout .

package main

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Sway IPC message types
const (
	ipcCommand       = 0
	ipcGetWorkspaces = 1
	ipcSubscribe     = 2
	ipcGetTree       = 4
	ipcGetVersion    = 7
)

var ipcMagic = []byte("i3-ipc")

// LayoutNode represents a node in the layout tree
type LayoutNode struct {
	Path     string
	Layout   string
	Children []*LayoutNode
	IsApp    bool
	AppCmd   string
}

// AppInfo contains launch information for an app
type AppInfo struct {
	Cmd       string
	Workspace string
	Path      string
}

// WindowEvent from sway IPC
type WindowEvent struct {
	Change    string `json:"change"`
	Container struct {
		ID  int `json:"id"`
		PID int `json:"pid"`
	} `json:"container"`
}

// Config is the JSON configuration structure
type Config struct {
	Workspaces map[string]interface{} `json:"workspaces"`
}

func main() {
	if len(os.Args) < 2 {
		// Default: load from standard config location, no-op if missing
		home, _ := os.UserHomeDir()
		defaultConfig := filepath.Join(home, ".config/sway/layouts/startup.json")
		if _, err := os.Stat(defaultConfig); os.IsNotExist(err) {
			// No config file, nothing to do
			os.Exit(0)
		}
		runLayout(defaultConfig, false)
		return
	}

	if os.Args[1] == "spawn" {
		runSpawn(os.Args[2:])
		return
	}

	// Parse flags for layout mode
	force := false
	configPath := ""
	for _, arg := range os.Args[1:] {
		if arg == "--force" || arg == "-f" {
			force = true
		} else if !strings.HasPrefix(arg, "-") {
			configPath = arg
		}
	}

	if configPath == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s [--force] <config.yaml>\n", os.Args[0])
		os.Exit(1)
	}

	runLayout(configPath, force)
}

// runSpawn executes the spawn wrapper mode
// Format: spawn <workspace> <path> <command...>
func runSpawn(args []string) {
	if len(args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: spawn <workspace> <path> <command...>\n")
		os.Exit(1)
	}

	// args[0] = workspace, args[1] = path, args[2:] = command
	cmdStr := strings.Join(args[2:], " ")

	// Run the command via shell (don't exec - we need to stay in process tree)
	cmd := exec.Command("/bin/sh", "-lc", cmdStr)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	// Forward signals to child
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start command: %v\n", err)
		os.Exit(1)
	}

	// Forward signals in background
	go func() {
		for sig := range sigChan {
			cmd.Process.Signal(sig)
		}
	}()

	// Wait for command to finish
	if err := cmd.Wait(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			os.Exit(exitErr.ExitCode())
		}
		os.Exit(1)
	}
}

func waitForIPC() {
	var err error
	for i := 0; i < 50; i++ { // 5 seconds
		ipc, err = newSwayIPC()
		if err == nil {
			if ipc.GetVersion() == nil {
				return
			}
			ipc.Close()
		}
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Fprintf(os.Stderr, "Error: Cannot connect to sway IPC after 5 seconds: %v\n", err)
	os.Exit(1)
}

// runLayout executes the layout loading mode
func runLayout(configPath string, force bool) {
	waitForIPC()
	defer ipc.Close()

	config, err := loadConfig(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading config: %v\n", err)
		os.Exit(1)
	}

	if len(config.Workspaces) == 0 {
		fmt.Println("No workspaces defined")
		os.Exit(0)
	}

	// Build layout trees and collect apps
	workspaceTrees := make(map[string]*LayoutNode)
	var allApps []AppInfo

	for wsName, wsDef := range config.Workspaces {
		tree := buildLayoutTree(wsDef, "")
		workspaceTrees[wsName] = tree
		collectApps(tree, wsName, &allApps)
	}

	// Check if target workspaces already have windows
	if !force {
		occupiedWorkspaces := getWorkspacesWithWindows()
		var conflicts []string
		for wsName := range workspaceTrees {
			if occupiedWorkspaces[wsName] {
				conflicts = append(conflicts, wsName)
			}
		}
		if len(conflicts) > 0 {
			fmt.Printf("Workspaces %v already have windows. Use --force to override.\n", conflicts)
			os.Exit(0)
		}
	}

	if len(allApps) == 0 {
		fmt.Println("No apps to launch")
		os.Exit(0)
	}

	fmt.Printf("Launching %d apps...\n", len(allApps))

	// Start event listener
	events := make(chan WindowEvent, 100)
	stopListener := make(chan struct{})
	listenerReady := make(chan struct{})
	go subscribeToEvents(events, stopListener, listenerReady)
	<-listenerReady

	expected := launchApps(allApps)
	placedByWs := collectWindows(events, expected)
	close(stopListener)

	// Arrange each workspace
	fmt.Println("\nArranging layouts...")
	for ws, tree := range workspaceTrees {
		if windows, ok := placedByWs[ws]; ok {
			arrangeWorkspace(ws, tree, windows)
		}
	}

	// Return to first workspace (preserve order from config)
	for wsName := range config.Workspaces {
		fmt.Printf("\nReturning to workspace %s\n", wsName)
		swaymsg(fmt.Sprintf("workspace %s", wsName))
		break
	}

	fmt.Println("\nLayout complete.")
}

func collectWindows(events <-chan WindowEvent, expected int) map[string]map[string]int {
	fmt.Printf("\nWaiting for %d windows...\n", expected)

	placedByWs := make(map[string]map[string]int)
	placedCount := 0
	quietDeadline := time.Now().Add(30 * time.Second)
	quietTimeout := 3 * time.Second

	for {
		select {
		case event := <-events:
			if event.Change == "new" && event.Container.ID != 0 && event.Container.PID != 0 {
				conID := event.Container.ID
				fmt.Printf("  New window: con_id=%d, pid=%d\n", conID, event.Container.PID)

				// Immediately hide in scratchpad to prevent flickering
				swaymsg(fmt.Sprintf("[con_id=%d] move scratchpad", conID))

				ws, path := findSpawnMetadata(event.Container.PID)
				if ws != "" && path != "" {
					if placedByWs[ws] == nil {
						placedByWs[ws] = make(map[string]int)
					}
					placedByWs[ws][path] = conID
					placedCount++
					fmt.Printf("    Tracked: workspace=%s, path=%s\n", ws, path)
				} else {
					fmt.Printf("    No placement metadata found (external window?)\n")
					// Show external windows back (not ours to manage)
					swaymsg(fmt.Sprintf("[con_id=%d] scratchpad show", conID))
				}
				quietDeadline = time.Now().Add(quietTimeout)
			}

		case <-time.After(500 * time.Millisecond):
			// Check completion conditions
		}

		if placedCount >= expected {
			fmt.Printf("\nAll %d windows placed\n", expected)
			break
		}

		if time.Now().After(quietDeadline) {
			fmt.Printf("\nQuiet timeout reached (%d/%d windows placed)\n", placedCount, expected)
			break
		}
	}

	return placedByWs
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

var layoutTypes = map[string]bool{
	"splith": true, "splitv": true, "tabbed": true, "stacking": true,
}

// buildLayoutTree parses a workspace definition into a layout tree.
// Format: {"layout": [...children...]} where children are commands (strings) or nested containers.
func buildLayoutTree(wsDef interface{}, basePath string) *LayoutNode {
	return parseNode(wsDef, basePath, "splith")
}

func parseNode(node interface{}, path string, parentLayout string) *LayoutNode {
	// String = app command
	if cmd, ok := node.(string); ok {
		return &LayoutNode{Path: path, IsApp: true, AppCmd: cmd}
	}

	// Map = container with layout key
	m, ok := node.(map[string]interface{})
	if !ok {
		return nil
	}

	// Find the layout key (tabbed, splitv, etc.)
	var layout string
	var children []interface{}
	for key, val := range m {
		if layoutTypes[key] {
			layout = key
			children, _ = val.([]interface{})
			break
		}
	}

	if layout == "" {
		layout = parentLayout
	}

	result := &LayoutNode{Path: path, Layout: layout}

	for i, child := range children {
		childPath := strconv.Itoa(i)
		if path != "" {
			childPath = path + "." + childPath
		}
		if childNode := parseNode(child, childPath, layout); childNode != nil {
			result.Children = append(result.Children, childNode)
		}
	}

	return result
}

func collectApps(node *LayoutNode, workspace string, apps *[]AppInfo) {
	if node.IsApp {
		if node.AppCmd != "" {
			*apps = append(*apps, AppInfo{
				Cmd:       node.AppCmd,
				Workspace: workspace,
				Path:      node.Path,
			})
		}
		return
	}

	for _, child := range node.Children {
		collectApps(child, workspace, apps)
	}
}

func launchApps(apps []AppInfo) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot find own executable: %v\n", err)
		return 0
	}

	count := 0
	for _, app := range apps {
		fmt.Printf("  Launching: %s (ws=%s, path=%s)\n", app.Cmd, app.Workspace, app.Path)

		cmd := exec.Command(self, "spawn", app.Workspace, app.Path, app.Cmd)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}

		if err := cmd.Start(); err != nil {
			fmt.Fprintf(os.Stderr, "    Failed to launch: %v\n", err)
			continue
		}
		count++
	}

	return count
}

func subscribeToEvents(events chan<- WindowEvent, stop <-chan struct{}, ready chan<- struct{}) {
	sock := os.Getenv("SWAYSOCK")
	if sock == "" {
		close(ready)
		return
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		close(ready)
		return
	}

	go func() {
		<-stop
		conn.Close()
	}()

	// Send subscribe request for window events
	payload := []byte(`["window"]`)
	msg := make([]byte, 14+len(payload))
	copy(msg[0:6], ipcMagic)
	binary.LittleEndian.PutUint32(msg[6:10], uint32(len(payload)))
	binary.LittleEndian.PutUint32(msg[10:14], ipcSubscribe)
	copy(msg[14:], payload)

	if _, err := conn.Write(msg); err != nil {
		close(ready)
		return
	}

	// Signal ready after subscribe is sent
	close(ready)

	// Read events in a loop
	header := make([]byte, 14)
	for {
		if _, err := conn.Read(header); err != nil {
			return
		}

		respLen := binary.LittleEndian.Uint32(header[6:10])
		if respLen == 0 {
			continue
		}

		resp := make([]byte, respLen)
		if _, err := conn.Read(resp); err != nil {
			return
		}

		var event WindowEvent
		if err := json.Unmarshal(resp, &event); err == nil {
			events <- event
		}
	}
}

func findSpawnMetadata(pid int) (workspace, path string) {
	visited := make(map[int]bool)
	current := pid

	for current > 1 && !visited[current] {
		visited[current] = true

		cmdline := readCmdline(current)
		if hasSpawnMarker(cmdline) {
			ws, p := parseSpawnArgs(cmdline)
			if ws != "" && p != "" {
				return ws, p
			}
		}

		current = getPPID(current)
	}

	return "", ""
}

func readCmdline(pid int) []string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}

	var args []string
	for _, arg := range strings.Split(string(data), "\x00") {
		if arg != "" {
			args = append(args, arg)
		}
	}
	return args
}

func hasSpawnMarker(cmdline []string) bool {
	hasLayout, hasSpawn := false, false
	for _, arg := range cmdline {
		if strings.Contains(arg, "sway-layout") {
			hasLayout = true
		}
		if arg == "spawn" {
			hasSpawn = true
		}
	}
	return hasLayout && hasSpawn
}

func parseSpawnArgs(cmdline []string) (ws, path string) {
	// Find "spawn" in cmdline, then ws and path are the next two args
	for i, arg := range cmdline {
		if arg == "spawn" && i+2 < len(cmdline) {
			return cmdline[i+1], cmdline[i+2]
		}
	}
	return "", ""
}

func getPPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}

	// Format: pid (comm) state ppid ...
	// Find last ) to handle comm with spaces/parens
	s := string(data)
	idx := strings.LastIndex(s, ")")
	if idx == -1 {
		return 0
	}

	fields := strings.Fields(s[idx+1:])
	if len(fields) < 2 {
		return 0
	}

	ppid, _ := strconv.Atoi(fields[1])
	return ppid
}

func getWorkspacesWithWindows() map[string]bool {
	result := make(map[string]bool)

	if ipc == nil {
		return result
	}

	treeOutput, err := ipc.GetTree()
	if err != nil {
		return result
	}

	var tree map[string]interface{}
	if err := json.Unmarshal([]byte(treeOutput), &tree); err != nil {
		return result
	}

	findWorkspacesWithWindows(tree, "", result)
	return result
}

func findWorkspacesWithWindows(node map[string]interface{}, currentWs string, result map[string]bool) {
	nodeType, _ := node["type"].(string)
	name, _ := node["name"].(string)

	if nodeType == "workspace" {
		currentWs = name
	}

	// If this node has an app_id, the workspace has windows
	if _, hasAppID := node["app_id"]; hasAppID && currentWs != "" {
		result[currentWs] = true
	}

	// Recurse into children
	if nodes, ok := node["nodes"].([]interface{}); ok {
		for _, child := range nodes {
			if childMap, ok := child.(map[string]interface{}); ok {
				findWorkspacesWithWindows(childMap, currentWs, result)
			}
		}
	}
	if floatingNodes, ok := node["floating_nodes"].([]interface{}); ok {
		for _, child := range floatingNodes {
			if childMap, ok := child.(map[string]interface{}); ok {
				findWorkspacesWithWindows(childMap, currentWs, result)
			}
		}
	}
}

// SwayIPC handles communication with sway
type SwayIPC struct {
	conn net.Conn
}

func newSwayIPC() (*SwayIPC, error) {
	sock := os.Getenv("SWAYSOCK")
	if sock == "" {
		return nil, fmt.Errorf("SWAYSOCK not set")
	}

	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}

	return &SwayIPC{conn: conn}, nil
}

func (s *SwayIPC) Close() {
	if s.conn != nil {
		s.conn.Close()
	}
}

func (s *SwayIPC) send(msgType uint32, payload []byte) ([]byte, error) {
	// Build message: magic + length + type + payload
	msg := make([]byte, 14+len(payload))
	copy(msg[0:6], ipcMagic)
	binary.LittleEndian.PutUint32(msg[6:10], uint32(len(payload)))
	binary.LittleEndian.PutUint32(msg[10:14], msgType)
	copy(msg[14:], payload)

	if _, err := s.conn.Write(msg); err != nil {
		return nil, err
	}

	// Read response header
	header := make([]byte, 14)
	if _, err := s.conn.Read(header); err != nil {
		return nil, err
	}

	// Parse response length
	respLen := binary.LittleEndian.Uint32(header[6:10])

	// Read response payload
	resp := make([]byte, respLen)
	if respLen > 0 {
		if _, err := s.conn.Read(resp); err != nil {
			return nil, err
		}
	}

	return resp, nil
}

func (s *SwayIPC) Command(cmd string) (bool, string) {
	resp, err := s.send(ipcCommand, []byte(cmd))
	if err != nil {
		return false, ""
	}

	// Check for success in response
	var results []struct {
		Success bool   `json:"success"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(resp, &results); err != nil {
		return false, string(resp)
	}

	for _, r := range results {
		if !r.Success {
			fmt.Fprintf(os.Stderr, "    ipc error [%s]: %s\n", cmd, r.Error)
			return false, ""
		}
	}

	return true, string(resp)
}

func (s *SwayIPC) GetTree() (string, error) {
	resp, err := s.send(ipcGetTree, nil)
	return string(resp), err
}

func (s *SwayIPC) GetVersion() error {
	_, err := s.send(ipcGetVersion, nil)
	return err
}

// Global IPC connection (initialized in runLayout)
var ipc *SwayIPC

func swaymsg(cmd string) bool {
	if ipc == nil {
		return false
	}
	ok, _ := ipc.Command(cmd)
	return ok
}

func arrangeWorkspace(ws string, tree *LayoutNode, windowsByPath map[string]int) {
	if len(windowsByPath) == 0 {
		return
	}

	fmt.Printf("  Arranging workspace %s: %d windows, root layout=%s\n", ws, len(windowsByPath), tree.Layout)

	// Focus workspace
	swaymsg(fmt.Sprintf("workspace %s", ws))

	// Windows are already in scratchpad (moved there on creation)
	// Arrange the tree - this brings them out in the right structure
	arrangeTree(tree, windowsByPath, ws)
}

func arrangeTree(node *LayoutNode, windowsByPath map[string]int, ws string) int {
	if node.IsApp {
		conID, ok := windowsByPath[node.Path]
		if !ok {
			return 0
		}
		return conID
	}

	// Recursively arrange children first
	var childConIDs []int
	for _, child := range node.Children {
		conID := arrangeTree(child, windowsByPath, ws)
		if conID != 0 {
			childConIDs = append(childConIDs, conID)
		}
	}

	if len(childConIDs) == 0 {
		return 0
	}

	if len(childConIDs) == 1 {
		// Bring single child out of scratchpad
		swaymsg(fmt.Sprintf("[con_id=%d] scratchpad show", childConIDs[0]))
		swaymsg(fmt.Sprintf("[con_id=%d] floating disable", childConIDs[0]))
		// Set container layout if tabbed/stacking
		if node.Layout == "tabbed" || node.Layout == "stacking" {
			swaymsg("focus parent")
			swaymsg(fmt.Sprintf("layout %s", node.Layout))
		}
		return childConIDs[0]
	}

	first := childConIDs[0]
	rest := childConIDs[1:]
	markPath := node.Path
	if markPath == "" {
		markPath = "root"
	}
	mark := fmt.Sprintf("_layout_%s", strings.ReplaceAll(markPath, ".", "_"))

	fmt.Printf("    Grouping %d windows at path '%s' with layout %s\n", len(childConIDs), node.Path, node.Layout)

	// Bring first window out and mark it as anchor
	swaymsg(fmt.Sprintf("[con_id=%d] scratchpad show", first))
	swaymsg(fmt.Sprintf("[con_id=%d] floating disable", first))
	swaymsg(fmt.Sprintf("[con_id=%d] mark --add %s", first, mark))

	// Set split direction before bringing in other windows
	switch node.Layout {
	case "splitv":
		swaymsg("split vertical")
	case "splith":
		swaymsg("split horizontal")
	}

	// Bring others out and move to anchor's container using mark
	for _, conID := range rest {
		swaymsg(fmt.Sprintf("[con_id=%d] scratchpad show", conID))
		swaymsg(fmt.Sprintf("[con_id=%d] floating disable", conID))
		swaymsg(fmt.Sprintf("[con_id=%d] move to mark %s", conID, mark))
	}

	// Set container layout
	swaymsg(fmt.Sprintf("[con_id=%d] focus", first))
	swaymsg("focus parent")
	swaymsg(fmt.Sprintf("layout %s", node.Layout))

	// Clean up mark
	swaymsg(fmt.Sprintf("[con_id=%d] unmark %s", first, mark))

	return first
}
