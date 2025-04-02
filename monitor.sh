#!/bin/bash

process_name="EncryptFilesInFolder"
while true; do
    # Check if the process is running using `pgrep`
    if pgrep -x "$process_name" > /dev/null
    then
        echo "Encryption process is running!"
        
        # Alert user (can use notify-send for graphical notification on Linux)
        notify-send "Alert" "The encryption process is running!"
        
        # Optionally kill the process (uncomment the next line to stop the process)
        # pkill "$process_name"

        break
    fi

    # Wait before checking again
    sleep 1
done