package main

import "embed"

//go:embed templates/*.html static/*
var templateFS embed.FS

//go:embed static/*
var staticFS embed.FS
