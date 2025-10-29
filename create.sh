#!/bin/bash

# ─── Constants ────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─── Color Output ─────────────────────────────────────────────────────────────
green='\033[0;32m'
red='\033[0;31m'
yellow='\033[1;33m'
reset='\033[0m'

# ─── Functions ─────────────────────────────────────────────────────────────

add_ctf() {
	TARGET="ctfs/$SLUG"
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
}

add_writeups() {
    echo -e "${yellow}Proceeding to add writeups to content/ctfs/$SLUG...${reset}"
	while true; do
		echo ""
		read -p "Enter writeup title: " WRITEUP_TITLE
		WRITEUP_SLUG=$(echo "$WRITEUP_TITLE" | tr ' ' '_')

		WRITEUP_PATH="ctfs/$SLUG/$WRITEUP_SLUG.md"
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
}

add_event() {
	read -p "Enter the date of the event (format: YYYY-MM-DD): " DATE
	read -p "Enter the hour of the event (format: HH:MM): " HOUR
	read -p "Enter the event location: " LOCATION
	TARGET="events/$SLUG.md"
	
	if [[ "$1" == "seminar" ]]; then
		echo -e "${green}Creating an event page in content/events...${reset}"
		DATETIME="${DATE}T${HOUR}"
		export HUGO_EVENT_DATETIME="$DATETIME:00+02:00"
		output=$(hugo new --kind seminar "$TARGET" 2>&1)
		unset HUGO_EVENT_DATETIME
		exit_code=$?

		if [[ $exit_code -eq 0 ]]; then
			echo -e "${green}$output${reset}"
		else
			echo -e "${red}$output${reset}"
		fi

		while true; do
			read -p "Do you want to add a presentation? (y/n): " ADD_PRESENTATION
			if [[ $ADD_PRESENTATION =~ ^[Yy]$ ]]; then
				read -p "Enter the description: " DESCRIPTION
				read -p "Enter the author: " AUTHOR
				read -p "Enter link for slides (or leave empty): " SLIDES
				if [[ -z "$SLIDES" ]]; then
					SLIDES="N/A"
				else
					SLIDES="[Link]($SLIDES)"
				fi
				echo -e "| ${DESCRIPTION} | ${AUTHOR} | ${LOCATION} | $(date -d "$DATETIME" +"%d %b %Y %H:%M") | ${SLIDES} |" >> "${SCRIPT_DIR}/content/${TARGET}"

			else
				echo -e "${green}Done!${reset}"
				exit 0
			fi
		done
		
		
		exit 0
	fi

	echo -e "${green}Creating an event directory and index page...${reset}"
	DATETIME="${DATE}T${HOUR}:00+02:00"
	export HUGO_EVENT_DATETIME="$DATETIME"
	export HUGO_EVENT_LOCATION="$LOCATION"
	output=$(hugo new --kind event "$TARGET" 2>&1)
	unset HUGO_EVENT_DATETIME
	unset HUGO_EVENT_LOCATION
	exit_code=$?

	if [[ $exit_code -eq 0 ]]; then
		echo -e "${green}$output${reset}"
	else
		echo -e "${red}$output${reset}"
	fi
	exit 0

}


# ─── Main ─────────────────────────────────────────────────────────────

echo "This script helps you create CTF directories and writeup files using the templates provided."
echo -e "\n${yellow}NOTE: The script will automatically replace spaces with underscores in titles.${reset}\n"

echo -e "[*] Latest seminar: $(ls content/events/ | grep -i 'seminar' | sort -r | head -n 1 | sed 's/.md//g' | sed 's/_/ /g')\n"

# ─── Get Title and Slug ───────────────────────────────────────────────────
read -p "Enter the object name: " NAME
SLUG=$(echo "$NAME" | tr ' ' '_')


# Skip choosing action if seminar detected in name
echo $SLUG | grep -i 'seminar' >/dev/null 2>&1
[ $? -eq 0 ] && echo -e "\n${yellow}Detected seminar - skipping action selection...${reset}"  && add_event seminar

# ─── Choose Action ────────────────────────────────────────────────────────────
echo -e "\n${green}What would you like to do with '$NAME'?${reset}"
select action in "Create new CTF" "Add writeups to existing CTF" "Add a new event"; do
    case $action in
        "Create new CTF" )
			add_ctf
            break;;
        "Add writeups to existing CTF" )
			add_writeups
            break;;
        "Add a new event" )
			add_event
            break;;
        * )
            echo -e "${red}Invalid option. Please choose 1 or 2.${reset}";;
    esac
done


