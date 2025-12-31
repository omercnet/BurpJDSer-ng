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
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;

import com.thoughtworks.xstream.XStream;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;

public class JDSer implements BurpExtension {

    URLTableComponent uiComponent;
    private static final byte[] SERIALIZE_MAGIC = new byte[] { (byte) 0xAC, (byte) 0xED };

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

    private record ByteRange(int startInclusive, int endExclusive) {
        int length() {
            return endExclusive - startInclusive;
        }
    }

    private static int indexOfBytes(byte[] data, byte[] needle, int startInclusive, int endExclusive) {
        if (data == null || needle == null || needle.length == 0) {
            return -1;
        }
        int lastStart = endExclusive - needle.length;
        for (int i = Math.max(0, startInclusive); i <= lastStart; i++) {
            boolean match = true;
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    match = false;
                    break;
                }
            }
            if (match) {
                return i;
            }
        }
        return -1;
    }

    private static int skipLeadingCrLf(byte[] data, int startInclusive, int endExclusive) {
        int i = startInclusive;
        while (i < endExclusive && (data[i] == '\r' || data[i] == '\n')) {
            i++;
        }
        return i;
    }

    private static boolean hasSerializeMagicAt(byte[] data, int offset, int endExclusive) {
        return offset >= 0
                && offset + SERIALIZE_MAGIC.length <= endExclusive
                && data[offset] == SERIALIZE_MAGIC[0]
                && data[offset + 1] == SERIALIZE_MAGIC[1];
    }

    private static ByteRange findSerializedRangeInMultipart(byte[] body) {
        if (body == null || body.length < 4 || body[0] != '-' || body[1] != '-') {
            return null;
        }

        int boundaryLineEnd = indexOfBytes(body, new byte[] { '\r', '\n' }, 0, body.length);
        if (boundaryLineEnd < 0) {
            boundaryLineEnd = indexOfBytes(body, new byte[] { '\n' }, 0, body.length);
        }
        if (boundaryLineEnd < 0 || boundaryLineEnd <= 2) {
            return null;
        }

        String boundary = new String(body, 2, boundaryLineEnd - 2, StandardCharsets.ISO_8859_1);
        if (boundary.isEmpty()) {
            return null;
        }

        byte[] delimiter = ("--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        byte[] nextBoundaryNeedle = ("\n--" + boundary).getBytes(StandardCharsets.ISO_8859_1);
        byte[] headersSepCrlf = new byte[] { '\r', '\n', '\r', '\n' };
        byte[] headersSepLf = new byte[] { '\n', '\n' };

        int boundaryStart = 0;
        while (boundaryStart >= 0 && boundaryStart < body.length) {
            if (boundaryStart + delimiter.length > body.length) {
                return null;
            }

            // final boundary: --boundary--
            int afterDelimiter = boundaryStart + delimiter.length;
            if (afterDelimiter + 1 < body.length && body[afterDelimiter] == '-' && body[afterDelimiter + 1] == '-') {
                return null;
            }

            int headersStart = boundaryStart + delimiter.length;
            if (headersStart + 1 < body.length && body[headersStart] == '\r' && body[headersStart + 1] == '\n') {
                headersStart += 2;
            } else if (headersStart < body.length && body[headersStart] == '\n') {
                headersStart += 1;
            } else if (boundaryStart == 0) {
                // If the body doesn't match the typical multipart format, fall back to non-multipart handling.
                return null;
            }

            int headersEnd = indexOfBytes(body, headersSepCrlf, headersStart, body.length);
            int headersSepLen = 4;
            if (headersEnd < 0) {
                headersEnd = indexOfBytes(body, headersSepLf, headersStart, body.length);
                headersSepLen = 2;
            }
            if (headersEnd < 0) {
                return null;
            }

            int partBodyStart = headersEnd + headersSepLen;
            int nextBoundaryNewlineIndex = indexOfBytes(body, nextBoundaryNeedle, partBodyStart, body.length);
            if (nextBoundaryNewlineIndex < 0) {
                return null;
            }

            int partBodyEndExclusive = nextBoundaryNewlineIndex;
            if (partBodyEndExclusive > partBodyStart && body[partBodyEndExclusive - 1] == '\r') {
                partBodyEndExclusive--;
            }

            int candidateStart = skipLeadingCrLf(body, partBodyStart, partBodyEndExclusive);
            if (hasSerializeMagicAt(body, candidateStart, partBodyEndExclusive)) {
                return new ByteRange(candidateStart, partBodyEndExclusive);
            }

            boundaryStart = nextBoundaryNewlineIndex + 1; // skip '\n', point at "--boundary"
        }

        return null;
    }

    private static ByteRange findSerializedRange(byte[] data) {
        if (data == null) {
            return null;
        }

        ByteRange multipartRange = findSerializedRangeInMultipart(data);
        if (multipartRange != null) {
            return multipartRange;
        }

        int index = indexOfBytes(data, SERIALIZE_MAGIC, 0, data.length);
        if (index < 0) {
            return null;
        }
        return new ByteRange(index, data.length);
    }

    public boolean isSerialized(byte[] data) {
        return findSerializedRange(data) != null;
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

        ByteRange range = findSerializedRange(data);
        if (range == null) {
            String errorMsg = "No Java serialization stream found in provided data.";
            uiComponent.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes(StandardCharsets.UTF_8));
        }

        try (ByteArrayInputStream bais = new ByteArrayInputStream(data, range.startInclusive(), range.length());
                CustomLoaderObjectInputStream ois = new CustomLoaderObjectInputStream(bais, classloader)) {
            Object obj = ois.readObject();
            return ByteArray.byteArray(xstream.toXML(obj).getBytes(StandardCharsets.UTF_8));
        } catch (IOException | ClassNotFoundException e) {
            String errorMsg = "Failed to deserialize data:" + e;
            uiComponent.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes(StandardCharsets.UTF_8));
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
            String errorMsg = "Failed to serialize data:" + e;
            uiComponent.addErrorLog(errorMsg);
            return ByteArray.byteArray(errorMsg.getBytes(StandardCharsets.UTF_8));
        }
    }

}
