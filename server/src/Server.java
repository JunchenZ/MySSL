import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;

public class Server {
  private ServerSocket server;
  private ArrayList<Socket> clients;
  
  public Server() throws IOException{
    server = new ServerSocket(8080);
    clients = new ArrayList<Socket>();
  }
  
  public Socket accept() throws IOException {
    Socket client =  server.accept();
    clients.add(client);
    return client;
  }
 
}
