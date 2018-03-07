#!/bin/bash

echo -n "Are you sure you want to uninstall? [y/n]"
read answer
if echo "$answer" | grep -iq "^y" ;then
    echo "Good, continuing..."
else
    echo "OK."
    exit
fi

DIR=/home/$(whoami)/bin

systemctl --user stop FCC.service
systemctl --user disable FCC.service
sudo rm /etc/systemd/user/FCC.service
rm -rf $DIR/FCC

echo "reset done."