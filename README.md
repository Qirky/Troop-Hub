# Troop Hub Service

Introducing the Troop Hub Service: making online live coding collaboration even easier! As long as the service is running you will be able to host your own publicly accessible Troop sessions with one easy command!

## Getting started

You'll need to have [Troop](https://github.com/qirky/troop) downloaded and know a bit about how it works first but then it's smooth sailing from there. To start a server hosted by the Troop Hub Service simply add the `--hub` flag when starting your server, followed by an identifiable name for your session like so:

`python run-server.py --hub mySession`

The console will then print out the IP address and port that the session is being run on. Now anyone can connect to that session as long as they have the password.

but to make things even easier, you can automatically pull this information into the client by using the same commands:

`python run-client.py --hub mySession`

Simple! Right now the service is only hosting a maximum of 10 concurrent sessions but if this proves a popular tool I'll look into crowdfunding to improve the server specs and increase that number.

## Running your own Troop Hub Service

It's also really easy to host your own Troop Hub Service but you will need to host it on a publicly accessible server and enable TCP communication on the ports you want to use - but more on that in a sec.

Before you start, make sure you have Troop downloaded somewhere on your server - you'll need it to spawn new instances of the server application. Next, get the Hub Service files by downloading or cloning this repository.

You have a choice now: you can copy the `troop-hub.py` file directly into the directory containing Troop's `run-server.py` file or you can specify the relative path to the file in `conf.json` - this defaults to `../Troop/`. Once you've done this just run:

`python troop-hub.py`

Now you're running a Troop Hub Service - thank you for taking part! As mentioned above, the service communicates on certain ports so you will have to allow TCP communication on these. By default these are 57990 - 58000 but you can change the range by specifying the lowest port number in `conf.txt`.

To connect to a custom Troop Hub Service, clients *will* need to know the service's IP address and port and use them to start their servers / clients and this is done via the command line by just adding values to `--hub` name like so:

`python run-server --hub myServer@<custom_hub_port>:port`

So if I was running the service on 144.144.144.144 and port 1234, I would create a server like this:

`python run-server --hub myServer@144.144.144.144:1234`
