# This Makefile is used to manage the olsonify-website project.
# 
# Variables:
# PROJECT_NAME - The name of the project.
#
# Commands:
# install - Installs the project dependencies using npm.
# start - Starts the development server using npm.
# build - Builds the project for production using npm.
# test - Runs the tests using npm.
# lint - Lints the project files using npm.
# clean - Removes the node_modules and dist directories.
#
# Phony targets:
# .PHONY - Declares the targets that are not actual files.
# Variables
PROJECT_NAME = topx-backend

# Commands
install:
	npm install

start:
	npm run start

test:
	npm run dev

lint:
	npm run lint

clean:
	rm -rf node_modules dist

# Phony targets
.PHONY: install start build test lint clean