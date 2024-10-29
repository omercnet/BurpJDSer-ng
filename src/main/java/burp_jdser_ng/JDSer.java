package burp_jdser_ng;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.URI;
import java.net.URISyntaxException;
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

    URLTableComponent uiComponent;
    final byte[] serializeMagic = new byte[] { -84, -19 };

    MontoyaApi api;

    public URLClassLoader customClassLoader = new URLClassLoader(new URL[] {});

    private XStream xstream;

    @Override
    public void initialize(MontoyaApi api) {
        api.logging().logToOutput("[+] Loading JDSer-NG...");
        this.api = api;
        this.uiComponent = new URLTableComponent(api);
        this.xstream = new XStream();

        api.extension().setName("BurpJDSer-NG");
        api.userInterface().registerHttpRequestEditorProvider(new JDSerRequestEditorProvider(api, this));
        api.userInterface().registerHttpResponseEditorProvider(new JDSerResponseEditorProvider(api, this));
        api.userInterface().registerSuiteTab("JDSer", uiComponent);

        this.uiComponent.reloadButton.addActionListener(l -> refreshSharedClassLoader());
        refreshSharedClassLoader();
        api.logging().logToOutput("[+] JDSer-NG loaded.");
    }

    public boolean isSerialized(byte[] data) {
        return api.utilities().byteUtils().indexOf(data, serializeMagic, false, 0, data.length) > -1;
    }

    public void refreshSharedClassLoader() {
        uiComponent.clearDiscoveredClassesLog();
        try {
            uiComponent.clearDiscoveredClassesLog();
            URL[] urlArray = uiComponent.getURLs();
            customClassLoader.close();
            customClassLoader = new URLClassLoader(urlArray);
            xstream.setClassLoader(customClassLoader);

            for (URL url : urlArray) {
                findClassesInJar(url.toString(), customClassLoader);
            }
        } catch (IOException | URISyntaxException ex) {
            uiComponent.addErrorLog("Error refreshing class loader: " + ex);
        }
    }

    private void findClassesInJar(String jarPath, ClassLoader classLoader) throws URISyntaxException {
        findClassesInJar(new File(new URI(jarPath)), classLoader);
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
                        uiComponent.addDiscoveredClassLog(clazz.getName());
                        xstream.allowTypes(new Class[] { clazz });
                    } catch (ClassNotFoundException e) {
                        String errorMsg = "Error loading class from jar (" + jarFile + "): " + e;
                        api.logging().logToError(errorMsg);
                        uiComponent.addErrorLog(errorMsg);
                    }
                }
            }
        } catch (IOException e) {
            uiComponent.addErrorLog("Error loading class from jar (" + jarFile + "): " + e);
        }
    }

    public ByteArray ByteArrayToXML(byte[] data, ClassLoader classloader) {

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data);
                CustomLoaderObjectInputStream ois = new CustomLoaderObjectInputStream(bais, classloader)) {
            Object obj = ois.readObject();
            return ByteArray.byteArray(xstream.toXML(obj).getBytes());
        } catch (IOException | ClassNotFoundException e) {
            String errorMsg = "Failed to serialize data:" + e;
            uiComponent.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes());
        }
    }

    public ByteArray XMLToByteArray(String data) {
        Object obj = xstream.fromXML(data);

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(obj);
            oos.flush();
            return ByteArray.byteArray(baos.toByteArray());
        } catch (IOException e) {
            String errorMsg = "Failed to deserialize data:" + e;
            uiComponent.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes());
        }
    }

}
