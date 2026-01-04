#!/bin/bash
retval=1
cmd='./tor-dl -d downloads -force -allow-http http://example3vad6cuxsjll4qjomyaaaoyvnyqppro75pazadzctrexample.onion/subdir/file.rar'
while [ $retval -eq 1 ]; do
   echo $cmd
   $cmd
   retval=$?
   sleep 600
done
