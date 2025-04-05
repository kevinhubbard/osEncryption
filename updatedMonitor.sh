#!/bin/bash

# Define the directory you want to monitor
monitor_dir="/path/to/your/directory"
process_name="EncryptFilesInFolder"

# Run an infinite loop to monitor file changes
while true; do
    # Use inotifywait to watch for file modifications, creations, or deletions
    echo "Monitoring directory for changes: $monitor_dir"
    
    # The `inotifywait` command waits for events (modifications, creations, deletions)
    # It will block until one of the events is triggered
    inotifywait -r -e modify,create,delete --format '%w%f' "$monitor_dir" | while read file; do
        echo "File change detected: $file"
        
        # Alert user when a file is changed/created/deleted
        notify-send "Alert" "File changed: $file"

        # Optionally, check if encryption process is running
        if pgrep -af "java.*$process_name" > /dev/null; then
            echo "Encryption process is running!"

            # You can take action here, like killing the process if desired
            # pkill "$process_name"  # Uncomment to kill the encryption process
        fi
    done

    # Optional: Add a sleep here if you want to pause before checking again (though `inotifywait` runs indefinitely)
    # sleep 1
done