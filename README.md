# testpmd-ui
testpmd UI

A web based testpmd GUI, major features:

- Generate testpmd start cmdline
- Generate flow command

Requirements:

- yum install python3-devel
- pip3 install flexx

Start:

- sudo ./testpmd-ui.py --app

Setup a remote server:

- sudo ./testpmd-ui.py --flexx-hostname=`hostname` --flexx-port=49190
- http://{hostname}:49190/TestpmdUI/

TBD:

- Add customize testpmd command line parameter.
- Add more match items and actions.
