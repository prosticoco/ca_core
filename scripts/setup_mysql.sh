#!/bin/bash
MYSQL_ROOT_PASSWORD=$1
echo 'create database coreCA' | mysql -uroot -p$MYSQL_ROOT_PASSWORD