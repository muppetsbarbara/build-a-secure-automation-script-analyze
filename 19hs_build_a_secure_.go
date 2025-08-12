package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/dgrijalva/jwt-go"
)

// Config holds the configuration for the script analyzer
type Config struct {
	SCRIPTDIR  string `json:"scriptdir"`
	SERVERADDR string `json:"serveraddr"`
	SERVERPORT int    `json:"serverport"`
	JWTSECRET  string `json:"jwtsecret"`
}

// Script holds the metadata for a script
type Script struct {
	Name     string `json:"name"`
	Filename string `json:"filename"`
	Content  string `json:"content"`
}

// Analyzer holds the logic for analyzing scripts
type Analyzer struct {
	config    Config
	scripts   map[string]Script
	jwtSecret []byte
}

// NewAnalyzer creates a new script analyzer instance
func NewAnalyzer(config Config) *Analyzer {
	return &Analyzer{
		config:    config,
		scripts:   make(map[string]Script),
		jwtSecret: []byte(config.JWTSECRET),
	}
}

// LoadScripts loads all scripts from the specified directory
func (a *Analyzer) LoadScripts() error {
	files, err := ioutil.ReadDir(a.config.SCRIPTDIR)
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.IsDir() {
			continue
		}
		if !strings.HasSuffix(file.Name(), ".sh") {
			continue
		}
		script, err := a.loadScript(file.Name())
		if err != nil {
			return err
		}
		a.scripts[script.Filename] = script
	}
	return nil
}

func (a *Analyzer) loadScript(filename string) (Script, error) {
	filepath := fmt.Sprintf("%s/%s", a.config.SCRIPTDIR, filename)
	content, err := ioutil.ReadFile(filepath)
	if err != nil {
		return Script{}, err
	}
	return Script{
		Name:     filename[:len(filename)-3],
		Filename: filename,
		Content: string(content),
	}, nil
}

// StartAnalyzer starts the script analyzer server
func (a *Analyzer) StartAnalyzer() error {
	http.HandleFunc("/analyze", a.handleAnalyze)
	http.HandleFunc("/scripts", a.handleScripts)
	log.Printf("Listening on %s:%d\n", a.config.SERVERADDR, a.config.SERVERPORT)
	return http.ListenAndServe(fmt.Sprintf("%s:%d", a.config.SERVERADDR, a.config.SERVERPORT), nil)
}

func (a *Analyzer) handleAnalyze(w http.ResponseWriter, r *http.Request) {
	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
		return a.jwtSecret, nil
	})
	if err != nil {
		http.Error(w, "Invalid token", http.StatusUnauthorized)
		return
	}
	scriptName := r.URL.Query().Get("script")
	script, ok := a.scripts[scriptName]
	if !ok {
		http.Error(w, "Script not found", http.StatusNotFound)
		return
	}
	analysis := a.analyzeScript(script.Content)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(analysis)
}

func (a *Analyzer) handleScripts(w http.ResponseWriter, r *http.Request) {
	scriptList := make([]string, 0, len(a.scripts))
	for filename := range a.scripts {
		scriptList = append(scriptList, filename)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(scriptList)
}

func (a *Analyzer) analyzeScript(content string) map[string]interface{} {
	// TO DO: implement script analysis logic here
	return map[string]interface{}{}
}

func main() {
	config := Config{}
	configFile, err := os.Open("config.json")
	if err != nil {
		log.Fatal(err)
	}
	defer configFile.Close()
	json.NewDecoder(configFile).Decode(&config)
	analyzer := NewAnalyzer(config)
	err = analyzer.LoadScripts()
	if err != nil {
		log.Fatal(err)
	}
	err = analyzer.StartAnalyzer()
	if err != nil {
		log.Fatal(err)
	}
}