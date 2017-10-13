#!/bin/bash

if [ $(whoami) = "root" ]
then
    echo "Do not install with root access."
    exit
fi

echo -n "Did you configure the controller.ini File? [y/n]"
read answer
if echo "$answer" | grep -iq "^y" ;then
    echo "Good, continuing..."
else
    echo "Start setup.sh after configuring controller.ini!"
    exit
fi

mkdir /home/$(whoami)/bin
DIR=/home/$(whoami)/bin

echo "Installing FunctionChainingController!!"
echo "Copy to user binary directory..."
mkdir $DIR/FCC
cp -R SecAppManager $DIR/FCC/
cp -R templates $DIR/FCC/
cp start_controller.py $DIR/FCC/
cp controller.ini $DIR/FCC/
touch $DIR/FCC/fcc.log
echo "Copy done!"

echo "Installing service..."
sudo cp FCC.service /etc/systemd/user/

echo "enabling SAW.service!"
systemctl --user enable FCC.service
echo "starting service..."
systemctl --user start FCC.service
echo "Check systemctl --user status FCC.service to see if everything went well."
echo "If something went wrong, check $DIR/FCC/fcc.log!"