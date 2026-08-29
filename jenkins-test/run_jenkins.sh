#!/bin/bash
export WORKSPACE=$(pwd)
export JOB_NAME="express-hello"
export BUILD_NUMBER="12"
export DEMO_SCENARIO="NORMAL"
export TPSR_API_BASE_URL='http://localhost:3000' # wait, in Jenkins it was http://localhost:3000/api but routes don't have /api? Oh wait, in Jenkins script: -X POST "$TPSR_API_BASE_URL/submit". So it expects http://localhost:3000
