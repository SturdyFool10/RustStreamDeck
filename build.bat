@echo off

setlocal enabledelayedexpansion

cargo build | cargo build --release | cargo build --profile=dist
