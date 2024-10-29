package example;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.net.*;

public class Client {
    public static void main(String[] args) throws IOException, URISyntaxException {
        // Create a serialized object
        Person person = new Person("John Doe", 30);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
            oos.writeObject(person);
        }
        byte[] serializedObject = baos.toByteArray();

        // Create a URL object
        URL url = new URI("http://httpbin.org/post").toURL();

        // Create a proxy object
        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 8080));

        // Open a connection to the URL using the proxy
        HttpURLConnection connection = (HttpURLConnection) url.openConnection(proxy);

        // Set the request method to POST
        connection.setRequestMethod("POST");

        // Set the request body to the serialized object
        connection.setRequestProperty("Content-Type", "application/octet-stream");
        connection.setDoOutput(true);
        connection.getOutputStream().write(serializedObject);

        // Get the response code
        int responseCode = connection.getResponseCode();

        // Print the response code
        System.out.println("Response Code: " + responseCode);

        // Get the response message
        String responseMessage = connection.getResponseMessage();

        // Print the response message
        System.out.println("Response Message: " + responseMessage);
    }
}

record Person(String name, int age) implements Serializable {
}