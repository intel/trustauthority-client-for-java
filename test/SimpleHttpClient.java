import java.io.*;
import java.net.*;

public class SimpleHttpClient {
    public static void main(String[] args) throws IOException {
        String serverAddress = "localhost";
        int serverPort = 8080;

        // Open a socket connection to the server
        Socket socket = new Socket(serverAddress, serverPort);

        // Create input and output streams for communication with the server
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));

        // Send a GET request to the server
        out.println("GET / HTTP/1.1");
        out.println("Host: " + serverAddress);
        out.println();

        // Read and display the response from the server
        String line;
        while ((line = in.readLine()) != null) {
            System.out.println(line);
        }

        // Close streams and the socket
        out.close();
        in.close();
        socket.close();
    }
}
