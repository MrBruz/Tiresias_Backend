# Tiresias_Backend

## IMPORTANT, WORK ON THIS WILL NOW BE WINDING DOWN SINCE I WILL BE COLABERATING MY EFFORTS WITH HELPING DEVELOP "ONIONR"
## ALSO THE BOOTSTRAP SERVER(HOSTED ON MY SPARE LAPTOP) IS NOW OFFLINE. FOR TESTING YOU WILL NEED TO HARDCODE YOUR OWN BOOTSTRAP SERVERS IP

#### Repo for my work on the tiresias(backend part) project. Currently unfinished but feel free to have a look.
## Current Status: Alpha
### Most of core features of this program works but not all features have been added and documentation may be scarse.


## Main Focus/Goal:
### This project is meant to be an efficent and easy to use backend that focuses on being, Secure, Anonymous and Decentralised.

#### To get started all you need is a bootstrap server which helps nodes/users find each other. Think of them like trackers for torrents. 

#### Also for developers who just want to test this, is there is bootstrap server pre-built in(Hosted on my spare laptop lol).

## Info
### Tor must be running with the following settings enabled
#### ControlPort 9051
#### CookieAuthentication 1

### For a demo and a showcase of how this works, and how to use this in your own projects see,
### https://github.com/Footsiefat/Tiresias_mail_client/blob/main/tiresias_mail.py

### -This uses python3 and requires you install PySocks and rsa with Pip aswell as python3-stem ("sudo apt install python3-stem -y" for linux)
### -Tor must be running as the same user that your running tiresias with
### -You can toggle the feedback/debug by changing the value of "debugLevel" at the start when first set
### -The demo had a strange error on unix where the "input" line breaks if you enter a command, I havent found a solution to this yet.
### -If you find any bugs, suggestions or ideas please let me know in "issues"

## Features I need to add later on...
#### Third Party Trusted Authority for Verifying Identity
#### Using a server to look after and pass on messages if the user2 in (user1 ---msg> user2) is offline. 
#### Modifiying the above feature so "friends" can look after and pass on messages
#### Option for sending files rather than just "text"
#### Work on having profile pictures
#### Start working on features that could allow for discord servers and that sorta thing
