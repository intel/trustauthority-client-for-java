import java.io.*;
import java.net.*;

public class SimpleHttpServer {
    public static void main(String[] args) throws IOException {
        int port = 8080;

        // Create a server socket to listen on the specified port
        ServerSocket serverSocket = new ServerSocket(port);
        System.out.println("Server listening on port " + port);

        while (true) {
            // Accept incoming client connection
            Socket clientSocket = serverSocket.accept();
            System.out.println("Client connected: " + clientSocket.getInetAddress());

            // Create input and output streams for communication with the client
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);

            // Read the HTTP request from the client
            String request = in.readLine();
            System.out.println("Received request: " + request);

            // Send an HTTP response back to the client
            String response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nHello, this is amber server!";
            out.println(response);

            // Close streams and the client socket
            out.close();
            in.close();
            clientSocket.close();
        }
    }
}
