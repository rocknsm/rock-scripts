# A collection of Bro scripts

This is a collection of bro scripts that do some unique things. To use,
go to your `site` directory and check it out to a named item.

~~~~
cd /opt/bro/share/bro/site
git clone git@bitbucket.org:cyberdev/bro-scripts.git cyberdev
~~~~

Then, in your local.bro add the following at the bottom:

~~~~
# Load the cyberdev scripts
@load cyberdev
~~~~


This loads all the scripts defined in `__load__.bro`. If there's a script
that you'd like to use that is not in there, you can load it directly:


~~~~
# Load JSON util function
@load cyberdev/utils/json
~~~~

TODO
----

[ ] Cleanup scripts and add common header
[ ] Create skeleton script file as a starter
