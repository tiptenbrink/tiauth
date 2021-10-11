#!/bin/bash
RESULT=$(curl http://localhost:3031/alive)

if [ "${RESULT}" != "alive!" ]; then
  echo "Not alive!"
  exit 1;
fi
echo "${RESULT}"