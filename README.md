# Protect-Agent-Messages-with-Classic-Cryptography

## Setup
First make sure you are in a virtual machine

Open up a terminal and run these commands:

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install cryptography==49.0.0 pytest==9.1.1

If this does not work make sure python3 is installed

Then generate thhe standard ffdhe3072 parameter file using the following command:

openssl genpkey -genparam -algorithm DH -pkeyopt group:ffdhe3072 -out ffdhe3072.pem

Confirm that it has been created by running the following command:

openssl dhparam -in ffdhe3072.pem -text -noout | head -3

And look for the result:

DH Parameters: (3072 bit) and GROUP: ffdhe3072

