#!/bin/bash

# ─── Color Output ─────────────────────────────────────────────────────────────
green='\033[0;32m'
red='\033[0;31m'
yellow='\033[1;33m'
reset='\033[0m'

echo "This script helps you create CTF directories and writeup files using the templates provided."
echo -e "\n${yellow}NOTE: The script will automatically replace spaces with underscores in titles.${reset}\n"

# ─── Get CTF Title and Slug ───────────────────────────────────────────────────
read -p "Enter the CTF name: " CTF_NAME
CTF_SLUG=$(echo "$CTF_NAME" | tr ' ' '_')

# ─── Choose Action ────────────────────────────────────────────────────────────
echo -e "\n${green}What would you like to do with '$CTF_NAME'?${reset}"
select action in "Create new CTF" "Add writeups to existing CTF"; do
    case $action in
        "Create new CTF" )
            TARGET="ctfs/$CTF_SLUG"
            echo -e "${green}Creating CTF directory and index page...${reset}"
            output=$(hugo new --kind ctf "$TARGET" 2>&1)
            exit_code=$?

            if [[ $exit_code -eq 0 ]]; then
                echo -e "${green}$output${reset}"
            else
                echo -e "${red}$output${reset}"
            fi

            read -p "Do you want to add a writeup? (y/n): " ADD_ANOTHER
            if [[ ! $ADD_ANOTHER =~ ^[Yy]$ ]]; then
                echo -e "${green}Done!${reset}"
                exit 0
            fi

            break;;
        "Add writeups to existing CTF" )
            echo -e "${yellow}Proceeding to add writeups to content/ctfs/$CTF_SLUG...${reset}"
            break;;
        * )
            echo -e "${red}Invalid option. Please choose 1 or 2.${reset}";;
    esac
done

# ─── Loop to Add Writeups ─────────────────────────────────────────────────────
while true; do
    echo ""
    read -p "Enter writeup title: " WRITEUP_TITLE
    WRITEUP_SLUG=$(echo "$WRITEUP_TITLE" | tr ' ' '_')

    WRITEUP_PATH="ctfs/$CTF_SLUG/$WRITEUP_SLUG.md"
    output=$(hugo new --kind writeup "$WRITEUP_PATH" 2>&1)
    exit_code=$?

    if [[ $exit_code -eq 0 ]]; then
        echo -e "${green}$output${reset}"
    else
        echo -e "${red}$output${reset}"
    fi

    read -p "Do you want to add another writeup? (y/n): " ADD_ANOTHER
    if [[ ! $ADD_ANOTHER =~ ^[Yy]$ ]]; then
        echo -e "${green}Bye!${reset}"
        break
    fi
done
