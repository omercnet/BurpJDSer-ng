# BurpJDSer-ng

A Burp Extender plugin that deserializes Java objects and encodes them in XML using the [XStream](https://x-stream.github.io/) library.

Based in part on [khai-tran](https://github.com/khai-tran/BurpJDSer)'s work but written from scratch to work with the new Montoya API.

## Usage

### 1. Find and Download Client JAR Files
There are a few methods to locate the required JAR files containing the classes to be deserialized:
- If you have a `.jnlp` file, use [jnpdownloader](https://code.google.com/p/jnlpdownloader/).
- Locate JAR files in the browser cache.
- Look for JAR files in Burp proxy history.

### 2. Start Burp Plugin
Download the plugin from the [releases page](https://github.com/omercnet/BurpJDSer-ng/releases) and load it in the Extensions tab in Burp.

Use the `JDSer` tab to load the JAR files containing the classes you want to deserialize.

### 3. Inspect Serialized Java Traffic
Serialized Java content will automatically appear in the `Java Object` tab in appropriate locations (proxy history, interceptor, repeater, etc.). Any changes made to the XML will serialize back once you switch to a different tab or send the request.

If you get an error that a class was not found, you can add the JAR file containing that class in the `JDSer` tab and try again.