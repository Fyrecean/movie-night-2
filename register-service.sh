#!/bin/sh

systemctl disable hay-fever-theater.service
cp ./hay-fever-theater.service /etc/systemd/system/hay-fever-theater.service
systemctl daemon-reload
systemctl enable hay-fever-theater.service
systemctl start hay-fever-theater.service