#!/bin/sh
# 
# usage: rtpw_test <rtpw_commands>
# 
# tests the rtpw sender and receiver functions

RTPW="./rtpw"
DEST_PORT=9999
DURATION=3

key128=2b2edc5034f61a72345ca5986d7bfd0189aa6dc2ecab32fd9af74df6dfc6
key192=2b2edc5034f61a72345ca5986d7bfd0189aa6dc2ecab32fd9af74df6dfc60123456789012345
key256=2b2edc5034f61a72345ca5986d7bfd0189aa6dc2ecab32fd9af74df6dfc601234567890123456789012345678901

ARGS128="-k $key128 -a -e 128"
ARGS192="-k $key192 -a -e 192"
ARGS256="-k $key256 -a -e 256"

# First, we run "killall" to get rid of all existing rtpw processes.
# This step also enables this script to clean up after itself; if this
# script is interrupted after the rtpw processes are started but before
# they are killed, those processes will linger.  Re-running the script
# will get rid of them.

killall rtpw 2&>/dev/null
sleep 2

if test -x $RTPW; then

    
echo  $0 ": starting 128-bit rtpw receiver process... "

exec $RTPW $* $ARGS128 -r 127.0.0.1 $DEST_PORT &

receiver_pid=$!

echo $0 ": receiver PID = $receiver_pid"

sleep 1 

# verify that the background job is running
ps | grep -q $receiver_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 254
fi

echo  $0 ": starting 128-bit rtpw sender process..."

exec $RTPW $* $ARGS128 -s 127.0.0.1 $DEST_PORT  &

sender_pid=$!

echo $0 ": sender PID = $sender_pid"

# verify that the background job is running
ps | grep -q $sender_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 255
fi

sleep $DURATION

kill $receiver_pid
kill $sender_pid





echo  $0 ": starting 192-bit rtpw receiver process... "

exec $RTPW $* $ARGS192 -r 127.0.0.1 $DEST_PORT &

receiver_pid=$!

echo $0 ": receiver PID = $receiver_pid"

sleep 1 

# verify that the background job is running
ps | grep -q $receiver_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 254
fi

echo  $0 ": starting 192-bit rtpw sender process..."

exec $RTPW $* $ARGS192 -s 127.0.0.1 $DEST_PORT  &

sender_pid=$!

echo $0 ": sender PID = $sender_pid"

# verify that the background job is running
ps | grep -q $sender_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 255
fi

sleep $DURATION

kill $receiver_pid
kill $sender_pid




echo  $0 ": starting 256-bit rtpw receiver process... "

exec $RTPW $* $ARGS256 -r 127.0.0.1 $DEST_PORT &

receiver_pid=$!

echo $0 ": receiver PID = $receiver_pid"

sleep 1 

# verify that the background job is running
ps | grep -q $receiver_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 254
fi

echo  $0 ": starting 256-bit rtpw sender process..."

exec $RTPW $* $ARGS256 -s 127.0.0.1 $DEST_PORT  &

sender_pid=$!

echo $0 ": sender PID = $sender_pid"

# verify that the background job is running
ps | grep -q $sender_pid
retval=$?
echo $retval
if [ $retval != 0 ]; then
    echo $0 ": error"
    exit 255
fi

sleep $DURATION

kill $receiver_pid
kill $sender_pid








echo $0 ": done (test finished, how does it look?)"

else 

echo "error: can't find executable" $RTPW
exit 1

fi

# EOF


