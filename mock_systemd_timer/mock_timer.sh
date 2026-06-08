#!/usr/bin/env bash

ref="reference_file_location"
prog="desired_program"

mkdir -p $(dirname "$ref")

function updateRef {
   local r=$1
   next_date=$(date '+%Y-%m-01' -d 'next month')
   touch -d "$next_date" "$r"
}

function canRun {
   local r=$1
   now=($date "+%s")
   next_run=$(date -r $r "+%s")
   return (( $now >= $next_run ))
}


if [[ ! -e $ref ]]; then
   $prog
   updateRef $ref
   exit 0
fi

if canRun $ref; then
   $prog
   updateRef $ref
fi



