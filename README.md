#BurpJDSer-ng


A Burp Extender plugin, that will deserialized java objects and encode them in XML using the [Xtream](http://xstream.codehaus.org/) library.

Based in part on [khai-tran](https://github.com/khai-tran/BurpJDSer)'s work but written from scratch to work with the new Extender API introduced in Burp-1.5.01

##Usage

###1) Find and download client *.jar files
Few methods to locate the required jar files containing the classes we'll be deserializing.
* In case of a .jnlp file use [jnpdownloader](https://code.google.com/p/jnlpdownloader/)
* Locating jars in browser cache
* Looking for .jar in burp proxy history

Finally, create a "libs/" directory next to your burp.jar and put all the jars in it.

###2) Start Burp plugin
Download from [here](https://github.com/IOActive/BurpJDSer-ng/raw/master/dist/BurpJDSer-ng.jar) and simply load it in the Extender tab, the Output window will list all the loaded jars from ./libs/ 


###3) Inspect serialized Java traffic
Serialized Java content will automagically appear in the Deserialized Java input tab in appropriate locations (proxy history, interceptor, repeater, etc.)
Any changes made to the XML will serialize back once you switch to a different tab or send the request.

**Please note that if you mess up the XML schema or edit an object in a funny way, the re-serialization will fail and the error will be displayed in the input tab**

In case you need to add more JARs, right click anywhere and select "BurpJDSer-ng: Reload JARs"
