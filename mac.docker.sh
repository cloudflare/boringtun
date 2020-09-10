#!/bin/bash

# Borrowed from: https://github.com/linq2db/linq2db

# osx agent doesn't have docker pre-installed, so we need to do it manually
retries=0
brew cask install docker

# manually setup docker, as versions after 2.0.0.3-ce-mac81,31259 cannot be installed without mouse-fu :facepalm:
# thanks to https://github.com/docker/for-mac/issues/2359#issuecomment-607154849
# allow the app to run without confirmation
xattr -d -r com.apple.quarantine /Applications/Docker.app
# preemptively do docker.app's setup to avoid any gui prompts
sudo /bin/cp /Applications/Docker.app/Contents/Library/LaunchServices/com.docker.vmnetd /Library/PrivilegedHelperTools
sudo /bin/cp /Applications/Docker.app/Contents/Resources/com.docker.vmnetd.plist /Library/LaunchDaemons/
sudo /bin/chmod 544 /Library/PrivilegedHelperTools/com.docker.vmnetd
sudo /bin/chmod 644 /Library/LaunchDaemons/com.docker.vmnetd.plist
sudo /bin/launchctl load /Library/LaunchDaemons/com.docker.vmnetd.plist

#open -g -a Docker.app || exit
open -g /Applications/Docker.app || exit

while ! docker info 2>/dev/null ; do
    sleep 5
    retries=`expr $retries + 1`
    if pgrep -xq -- "Docker"; then
        echo 'docker still running'
    else
        echo 'docker not running, restart'
        #open -g -a Docker.app || exit
        open -g /Applications/Docker.app || exit
    fi
    if [ $retries -gt 30 ]; then
        >&2 echo 'Failed to run docker'
        exit 1
    fi;

    echo 'Waiting for docker service to be in the running state'
done
