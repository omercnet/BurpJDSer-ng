package burp_jdser_ng;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.thoughtworks.xstream.XStream;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;

public class JDSer implements BurpExtension {

    private MontoyaApi api;
    private URLTableComponent urls;
    public ClassLoader customClassLoader;
    private final byte[] serializeMagic = new byte[]{-84, -19};

    private XStream xstream;

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        this.urls = new URLTableComponent(api);
        this.xstream = new XStream();

        refreshSharedClassLoader();
        api.extension().setName("BurpJDSer-NG");

        api.userInterface().registerHttpRequestEditorProvider(new JDSerRequestEditorProvider(api, this));
        api.userInterface().registerHttpResponseEditorProvider(new JDSerResponseEditorProvider(api, this));
        api.userInterface().registerSuiteTab("JDSer", urls);

        this.urls.reloadButton.addActionListener(l -> refreshSharedClassLoader());
    }

    public boolean isSerialized(byte[] data) {
        return api.utilities().byteUtils().indexOf(data, serializeMagic, false, 0, data.length) > -1;
    }

    public void refreshSharedClassLoader() {
        urls.clearDiscoveredClassesLog();
        URL[] urlArray = urls.getURLs();
        customClassLoader = new URLClassLoader(urlArray);
        this.xstream.setClassLoader(customClassLoader);

        for (URL url : urlArray) {
            // Get the directory or jar file that the URL points to
            File file = new File(url.getFile());

            // If the file is a directory, iterate over its contents
            if (file.getName().endsWith(".jar")) {
                findClassesInJar(file, customClassLoader);
            } else {
                this.urls.addErrorLog(file + " is not a recognized file type");
            }
        }
    }

    private void findClassesInJar(File jarFile, ClassLoader classLoader) {
        try (JarFile jar = new JarFile(jarFile)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                if (entry.getName().endsWith(".class")) {
                    String className = entry.toString().substring(0, entry.toString().length() - 6);
                    className = className.replace('/', '.');
                    try {
                        Class<?> clazz = classLoader.loadClass(className);
                        urls.addDiscoveredClassLog(clazz.getName());
                        xstream.allowTypes(new Class[]{clazz});
                    } catch (ClassNotFoundException e) {
                        urls.addErrorLog("Error loading class from jar (" + jarFile + "): " + e);
                    }
                }
            }
        } catch (IOException e) {
            urls.addErrorLog("Error loading class from jar (" + jarFile + "): " + e);
        }
    }

    public ByteArray ByteArrayToXML(byte[] data, ClassLoader classloader) {

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data); CustomLoaderObjectInputStream ois = new CustomLoaderObjectInputStream(bais, classloader)) {
            Object obj = ois.readObject();
            urls.addDiscoveredClassLog(obj.getClass().getName());
            return ByteArray.byteArray(xstream.toXML(obj).getBytes());
        } catch (IOException | ClassNotFoundException e) {
            String errorMsg = "Failed to serialize data:" + e;
            urls.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes());
        }
    }

    public ByteArray XMLToByteArray(String data) {
        Object obj = xstream.fromXML(data);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            oos.flush();
            return ByteArray.byteArray(baos.toByteArray());
        } catch (IOException e) {
            String errorMsg = "Failed to deserialize data:" + e;
            urls.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes());
        }
    }

}
