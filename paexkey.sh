#!/bin/bash

max_processes=300  # Maximum number of parallel processes
current_processes=40  # Start with 40 process
delay_seconds=1

find bug_bounty -type f -print0 | while read -d $'\0' file; do
  # Run the command for the current file
  cat "$file" | go run paexkey_unleashed.go -t 200 -subs -s -w -u -timeout 6 -k keywords | flock -x bugbounty.paexkey -c 'tee -a bugbounty.paexkey' &

  sleep "$delay_seconds"
  
  # Increment the current process count
  ((current_processes++))

  # If we reach the maximum number of processes, wait for them to finish
  if [ "$current_processes" -ge "$max_processes" ]; then
    wait
    current_processes=40
  fi
done

# Wait for any remaining processes to finish
wait
