#!/bin/bash

# Directory to monitor
monitor_dir="/home/kevin/Projects/Java/osEncryption/encryptionTest"

echo "[Antivirus] Monitoring directory: $monitor_dir"
echo "[Antivirus] Press Ctrl+C to stop monitoring."

# Ask the user for input from the actual terminal (not the redirected pipe)
prompt_user() {
    echo "stopped. Would you like to continue (Y/N)?"
    read -r -p "" input < /dev/tty
    #echo "[Debug] You entered: $input"
    if [[ "$input" == "y" || "$input" == "Y" ]]; then
        echo "[Antivirus] Resuming process $pid"
        kill -CONT "$pid"
    elif [[ "$input" == "n" || "$input" == "N" ]]; then
        echo "[Antivirus] Killing process $pid"
        kill -9 "$pid"
    else
        echo "[Antivirus] Invalid input. Skipping process."
    fi
}

# Infinite loop to keep watching
while true; do
    while read file; do
        echo -e "\n[ALERT] Change detected in: $file"

        lsof_output=$(lsof "$file" 2>/dev/null)

        if [[ -z "$lsof_output" ]]; then
            echo "[Antivirus] No process found using the file."
            continue
        fi

        pid=$(echo "$lsof_output" | awk 'NR==2 {print $2}')
        process_name=$(echo "$lsof_output" | awk 'NR==2 {print $1}')

        if [[ -z "$pid" ]]; then
            echo "[Antivirus] Could not find PID for the process using $file."
            continue
        fi

        echo "[Antivirus] Suspicious process detected:"
        echo "  PID: $pid"
        echo "  Name: $process_name"

        kill -STOP "$pid" && echo "[Antivirus] Process $pid paused."

        if [[ "$(ps -o stat= -p $pid)" == T* ]]; then
            prompt_user
        else
            echo "[Antivirus] Process $pid is not stopped."
        fi

    done < <(inotifywait -r -e modify,create,delete --format '%w%f' "$monitor_dir" 2>/dev/null)
done