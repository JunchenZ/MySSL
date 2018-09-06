import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;


public class ServerDriver {

  public static void main(String[] args) throws Exception {
    Server server = new Server();
    while (true) {
      Socket client = server.accept();

      // get server's certificate
      FileInputStream fis = new FileInputStream("sslCertSigned.cert");
      BufferedInputStream bis = new BufferedInputStream(fis);
      CertificateFactory cf = CertificateFactory.getInstance("X.509");
      Certificate cert = cf.generateCertificate(bis);
      PublicKey pub = cert.getPublicKey();
      cert.verify(pub);

      // verify server's public key
      File f = new File("pub.der");
      fis = new FileInputStream(f);
      DataInputStream dis = new DataInputStream(fis);
      byte[] pubBlob = new byte[(int) f.length()];
      dis.readFully(pubBlob);
      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PublicKey pub2 = keyFactory.generatePublic(new X509EncodedKeySpec(pubBlob));
      if (pub.equals(pub2)) {
        System.out.println("public key verified!");
      } else {
        System.out.println("public key verification failed!");
      }
      dis.close();
      
      // get server's private key
      File f2 = new File("prv.der");
      FileInputStream fis3 = new FileInputStream(f2);
      DataInputStream dis2 = new DataInputStream(fis3);
      byte[] prvBlob = new byte[(int) f2.length()];
      dis2.readFully(prvBlob);
      PrivateKey prv = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(prvBlob));
      dis2.close();
      
      // generate server's nonce
      SecureRandom rand = new SecureRandom();
      byte[] rs = new byte[20];
      rand.nextBytes(rs);

      // 2. get client's public key from client's certificate
      BufferedInputStream bis2 = new BufferedInputStream(client.getInputStream());
      DataInputStream dis3 = new DataInputStream(bis2);
      int length = dis3.readInt();
      byte[] pubBlob2 = new byte[length];
      dis3.readFully(pubBlob2);
      InputStream in = new ByteArrayInputStream(pubBlob2);
      CertificateFactory cf2 = CertificateFactory.getInstance("X.509");
      Certificate cert2 = cf2.generateCertificate(in);
      PublicKey pubClient = cert2.getPublicKey();

      // send server's certificate
      OutputStream os = client.getOutputStream();
      DataOutputStream dos = new DataOutputStream(os);
      dos.writeInt(cert.getEncoded().length);
      dos.write(cert.getEncoded());
      dos.flush();

      // encrypt server's nonce with client's public key and send it
      OutputStream os2 = client.getOutputStream();
      DataOutputStream dos2 = new DataOutputStream(os2);
      Cipher c = Cipher.getInstance("RSA");
      c.init(Cipher.ENCRYPT_MODE, pubClient);
      byte[] kcrs = c.doFinal(rs);
      dos2.writeInt(kcrs.length);
      dos2.write(kcrs);
      dos2.flush();

      // 4. get client's nonce
      BufferedInputStream bis3 = new BufferedInputStream(client.getInputStream());
      DataInputStream dis4 = new DataInputStream(bis3);
      int length2 = dis4.readInt();
      byte[] ksrc = new byte[length2];
      dis4.readFully(ksrc);
      Cipher c2 = Cipher.getInstance("RSA");
      c2.init(Cipher.DECRYPT_MODE, prv);
      byte[] rc = c2.doFinal(ksrc);

      // calculate master key
      byte[] k = new byte[20];
      int i = 0;
      for (byte b : rs) {
        k[i] = (byte) (b ^ rc[i]);
      }

      // 4. compute message1
      byte[] msg1 = new byte[pub.getEncoded().length + rs.length + rc.length + k.length];
      int index = 0;
      System.arraycopy(pub.getEncoded(), 0, msg1, index, pub.getEncoded().length);
      index += pub.getEncoded().length;
      System.arraycopy(rs, 0, msg1, index, rs.length);
      index += rs.length;
      System.arraycopy(rc, 0, msg1, index, rc.length - 1);
      index += rc.length;
      System.arraycopy(k, 0, msg1, index, k.length);

      // compute and send hash1
      MessageDigest md = MessageDigest.getInstance("SHA-1");
      byte[] hash1 = md.digest(msg1);
      byte[] serverString = "SERVER".getBytes();
      byte[] appended = new byte[hash1.length + serverString.length];
      System.arraycopy(hash1, 0, appended, 0, hash1.length);
      System.arraycopy(serverString, 0, appended, hash1.length, serverString.length);
      OutputStream os3 = client.getOutputStream();
      DataOutputStream dos3 = new DataOutputStream(os3);
      Cipher c1 = Cipher.getInstance("RSA");
      c1.init(Cipher.ENCRYPT_MODE, pubClient);//294 bytes
      byte[] toSend = c.doFinal(appended);
      dos3.writeInt(toSend.length);
      dos3.write(toSend);
      dos3.flush();

      // 6. get client's hash2
      BufferedInputStream bis4 = new BufferedInputStream(client.getInputStream());
      DataInputStream dis5 = new DataInputStream(bis4);
      int length3 = dis5.readInt();
      byte[] encrypted1 = new byte[length3];
      dis5.readFully(encrypted1);
      Cipher c3 = Cipher.getInstance("RSA");
      c3.init(Cipher.DECRYPT_MODE, prv);
      byte[] appendedhash2 = c3.doFinal(encrypted1);
      byte[] clientString = new byte["CLIENT".length()];
      i = 0;
      for (int j = appendedhash2.length - clientString.length; j < appendedhash2.length; ++j) {
        clientString[i++] = appendedhash2[j];
      }
      byte[] clienthash2 = new byte[appendedhash2.length - clientString.length];
      i = 0;
      for (int j = 0; j < clienthash2.length; ++j) {
        clienthash2[i++] = appendedhash2[j];
      }
      if (Arrays.equals(clientString, "CLIENT".getBytes())) {
        System.out.println("client string verified!");
      } else {
        System.out.println("client string verification failed!");
      }
      
      // generate secret key
      SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
      random.setSeed(k);
      KeyGenerator keyGenerator = KeyGenerator.getInstance("DESede");
      keyGenerator.init(random);
      
      SecretKey serverAuthKey = keyGenerator.generateKey();
      SecretKey clientAuthKey = keyGenerator.generateKey();
      SecretKey serverEncKey = keyGenerator.generateKey();
      SecretKey clientEncKey = keyGenerator.generateKey();
      
      System.out.println("handshake successful!");
      
      // 7. read data for data transfer
      File file = new File("image.jpg");
      FileInputStream fis2 = new FileInputStream(file);
      byte[] seq = ByteBuffer.allocate(4).putInt(1).array();
      BufferedInputStream bis5 = new BufferedInputStream(fis2);
      DataInputStream dis6 = new DataInputStream(bis5);
      byte[] data = new byte[(int) file.length()];
      dis6.readFully(data);
      byte[] tomac = new byte[seq.length + data.length];
      System.arraycopy(seq, 0, tomac, 0, seq.length);
      System.arraycopy(data, 0, tomac, seq.length, data.length);
      dis6.close();
      
      // hash the seq # and data
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(serverAuthKey);
      byte[] hmac = mac.doFinal(tomac);
      mac.reset();
      
      // encrypt data and hmac
      byte[] toencrypt = new byte[((data.length + hmac.length) / 16 + 1) * 16];
      System.arraycopy(data, 0, toencrypt, 0, data.length);
      System.arraycopy(hmac, 0, toencrypt, data.length, hmac.length);
      Cipher c4 = Cipher.getInstance("DESede");
      c4.init(Cipher.ENCRYPT_MODE, serverEncKey);
      byte[] encrypted = c4.doFinal(toencrypt);
      
      // data transfer
      byte[] totransfer = new byte[seq.length + encrypted.length];
      System.arraycopy(seq, 0, totransfer, 0, seq.length);
      System.arraycopy(encrypted, 0, totransfer, seq.length, encrypted.length);
      OutputStream os4 = client.getOutputStream();
      DataOutputStream dos4 = new DataOutputStream(os4);
      dos4.writeInt(data.length);
      dos4.writeInt(totransfer.length);
      dos4.write(totransfer);
      dos4.flush();
      System.out.println("\nimage sent successfully!");
    }
  }
}