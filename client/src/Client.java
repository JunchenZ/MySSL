import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Client {
  Socket client;
  
  public Client() throws IOException {
    client = new Socket("localhost", 8080);
  }

  public OutputStream getOutputStream() throws IOException {
    return client.getOutputStream();
  }
  
  public InputStream getInputStream() throws IOException {
    return client.getInputStream();
  }
  
  public void close() throws IOException {
    client.close();
  }
  
}
